use super::utils::noise_simulation::CudaSideResources;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLweBootstrapResult, LweClassicFftBootstrap,
};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::CudaBlockInfo;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::IntegerCiphertext;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::noise_simulation::CudaDynLwe;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::unchecked_small_scalar_mul_integer;
use crate::integer::CompressedServerKey;
use crate::prelude::CastInto;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, MetaParameters};
use crate::shortint::server_key::tests::noise_distribution::dp_ks_ms::dp_ks_any_ms;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
use crate::shortint::{ClientKey, ShortintParameterSet};
use itertools::Itertools;
use rayon::prelude::*;

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint
fn sanity_check_encrypt_dp_ks_pbs_gpu(meta_params: MetaParameters) {
    let block_params = meta_params.compute_parameters;
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let max_scalar_mul = cuda_sks.max_noise_level.get();
    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let br_input_modulus_log = cuda_sks.br_input_modulus_log();
    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();

    // Need to generate the required indexes for the PBS
    let num_ct_blocks = 1;
    let mut lut_vector_indexes: Vec<u64> = vec![u64::ZERO; num_ct_blocks];
    for (i, ind) in lut_vector_indexes.iter_mut().enumerate() {
        *ind = <usize as CastInto<u64>>::cast_into(i);
    }
    let mut d_lut_vector_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &streams, 0) };
    unsafe { d_lut_vector_indexes.copy_from_cpu_async(&lut_vector_indexes, &streams, 0) };
    let lwe_indexes_usize: Vec<usize> = (0..num_ct_blocks).collect_vec();
    let lwe_indexes = lwe_indexes_usize
        .iter()
        .map(|&x| <usize as CastInto<u64>>::cast_into(x))
        .collect_vec();
    let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &streams, 0) };
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, &streams, 0) };
    unsafe {
        d_input_indexes.copy_from_cpu_async(&lwe_indexes, &streams, 0);
        d_output_indexes.copy_from_cpu_async(&lwe_indexes, &streams, 0);
    }
    streams.synchronize();

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(block_params.message_modulus().0 - 1),
        message_modulus: block_params.message_modulus(),
        carry_modulus: block_params.carry_modulus(),
        atomic_pattern: block_params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let mut cuda_side_resources = CudaSideResources::new(&streams, block_info);

    for _ in 0..10 {
        let ct_input = cks.key.encrypt(0);
        let cloned_ct_input = ct_input.clone();
        let radix_ct_input = crate::integer::RadixCiphertext::from_blocks(vec![ct_input]);
        let d_ct_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &radix_ct_input,
            &cuda_side_resources.streams,
        );
        let gpu_sample_input = CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks);

        let (_input, _after_dp, _after_ks, _before_ms, after_ms) = dp_ks_any_ms(
            gpu_sample_input,
            max_scalar_mul,
            &cuda_sks,
            modulus_switch_config,
            br_input_modulus_log,
            &mut cuda_side_resources,
        );

        let mut after_pbs = d_accumulator.allocate_lwe_bootstrap_result(&mut cuda_side_resources);
        cuda_sks.lwe_classic_fft_pbs(
            &after_ms,
            &mut after_pbs,
            &d_accumulator,
            &mut cuda_side_resources,
        );

        let after_pbs_ct = after_pbs.as_ct_64_cpu(&cuda_side_resources.streams);

        let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![cloned_ct_input]);
        let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &radix_ct,
            &cuda_side_resources.streams,
        );

        unchecked_small_scalar_mul_integer(
            &cuda_side_resources.streams,
            &mut d_ct.ciphertext,
            max_scalar_mul,
            block_params.message_modulus(),
            block_params.carry_modulus(),
        );

        let mut after_pbs_shortint_ct: CudaUnsignedRadixCiphertext =
            cuda_sks.create_trivial_zero_radix(1, &cuda_side_resources.streams);

        cuda_sks.apply_lookup_table(
            &mut after_pbs_shortint_ct.ciphertext,
            &d_ct.ciphertext,
            &id_lut,
            0..1,
            &cuda_side_resources.streams,
        );

        let shortint_res_list = after_pbs_shortint_ct
            .ciphertext
            .d_blocks
            .to_lwe_ciphertext_list(&cuda_side_resources.streams);
        let shortint_res_ct = LweCiphertext::from_container(
            shortint_res_list.clone().into_container(),
            shortint_res_list.ciphertext_modulus(),
        );
        assert_eq!(after_pbs_ct.as_view(), shortint_res_ct.as_view());
    }
}

create_gpu_parameterized_test!(sanity_check_encrypt_dp_ks_pbs_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

use crate::shortint::CarryModulus;
fn encrypt_dp_ks_any_ms_inner_helper_gpu(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let thread_cks: crate::integer::ClientKey;
    let thread_cuda_sks: CudaServerKey;

    let (cks, cuda_sks) = if should_use_single_key_debug() {
        (single_cks, single_cuda_sks)
    } else {
        let block_params: ShortintParameterSet = params.into();
        thread_cks = crate::integer::ClientKey::new(block_params);
        let thread_compressed_server_key =
            CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
        thread_cuda_sks =
            CudaServerKey::decompress_from_cpu(&thread_compressed_server_key, streams);
        (&thread_cks.key, &thread_cuda_sks)
    };
    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();

    let ct_input = cks.unchecked_encrypt(msg);
    let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct_input.ct, streams);
    let gpu_sample_input = CudaDynLwe::U64(d_ct_input);
    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let mut cuda_side_resources = CudaSideResources::new(streams, block_info);

    let (input_gpu, after_dp_gpu, after_ks_gpu, after_drift_gpu, after_ms_gpu) = dp_ks_any_ms(
        gpu_sample_input,
        scalar_for_multiplication,
        cuda_sks,
        modulus_switch_config,
        br_input_modulus_log,
        &mut cuda_side_resources,
    );
    cuda_side_resources.streams.synchronize();

    let input_ct = input_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_dp_ct = after_dp_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_ks_ct = after_ks_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_ms_ct = after_ms_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let before_ms_gpu: &CudaDynLwe = after_drift_gpu.as_ref().unwrap_or(&after_ks_gpu);
    let before_ms_ct = before_ms_gpu.as_ct_64_cpu(&cuda_side_resources.streams);

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new_from_lwe(
                &input_ct,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_dp_ct,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_ks_ct,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &before_ms_ct,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_ms_ct,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
        ),
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    }
}

fn encrypt_dp_ks_any_ms_noise_helper_gpu(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
) {
    let (input, after_dp, after_ks, before_ms, after_ms) = encrypt_dp_ks_any_ms_inner_helper_gpu(
        params,
        single_cks,
        single_cuda_sks,
        msg,
        scalar_for_multiplication,
        br_input_modulus_log,
        streams,
    );

    (
        input
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_dp
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ks
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        before_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
    )
}

fn encrypt_dp_ks_any_ms_pfail_helper_gpu(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> DecryptionAndNoiseResult {
    let (_input, _after_dp, _after_ks, after_ms, _after_pbs) =
        encrypt_dp_ks_any_ms_inner_helper_gpu(
            params,
            single_cks,
            single_cuda_sks,
            msg,
            scalar_for_multiplication,
            br_input_modulus_log,
            streams,
        );

    after_ms
}

/// GPU version of the noise checking test
fn noise_check_encrypt_dp_ks_ms_noise_gpu(params: MetaParameters) {
    let params = params.compute_parameters;
    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let modulus_switch_config_gpu = cuda_sks.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = cuda_sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config_gpu.expected_average_after_ms(params.polynomial_size());

    let max_scalar_mul = cuda_sks.max_noise_level.get();

    let (_input_sim, _after_dp_sim, _after_ks_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks.key, 0);
        dp_ks_any_ms(
            noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            br_input_modulus_log,
            &mut (),
        )
    };
    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let ct_input = cks.key.encrypt(0);
    let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct_input.ct, &streams);
    let gpu_sample_input = CudaDynLwe::U64(d_ct_input);
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        // Create CudaBlockInfo from parameters for this call
        let block_info = CudaBlockInfo {
            degree: crate::shortint::parameters::Degree::new(params.message_modulus().0 - 1),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            atomic_pattern: params.atomic_pattern(),
            noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
        };
        let mut side_resources = CudaSideResources::new(&streams, block_info);

        let (_input, _after_dp, _after_ks, _after_drift, after_ms) = dp_ks_any_ms(
            gpu_sample_input,
            max_scalar_mul,
            &cuda_sks,
            modulus_switch_config_gpu,
            br_input_modulus_log,
            &mut side_resources,
        );

        (after_ms.lwe_dimension(), after_ms.raw_modulus_float())
    };

    assert_eq!(after_ms_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_before_ms = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000usize;
    let chunk_size = 8;
    let vec_local_streams = (0..chunk_size)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();
    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &vec_local_streams[*i % chunk_size];
                        let (_input, _after_dp, _after_ks, before_ms, after_ms) =
                            encrypt_dp_ks_any_ms_noise_helper_gpu(
                                params,
                                &cks.key,
                                &cuda_sks,
                                0,
                                max_scalar_mul,
                                br_input_modulus_log,
                                local_stream,
                            );
                        (before_ms.value, after_ms.value)
                    })
                    .collect::<Vec<_>>()
            })
            .unzip();

        noise_samples_before_ms.extend(current_noise_sample_before_ms);
        noise_samples_after_ms.extend(current_noise_samples_after_ms);
    }

    let before_ms_normality = normality_check(&noise_samples_before_ms, "before ms", 0.01);

    let after_ms_is_ok = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        expected_average_after_ms,
        after_ms_sim.variance(),
        params.lwe_noise_distribution(),
        after_ms_sim.lwe_dimension(),
        after_ms_sim.modulus().as_f64(),
    );

    assert!(before_ms_normality.null_hypothesis_is_valid && after_ms_is_ok);
}

create_gpu_parameterized_test!(noise_check_encrypt_dp_ks_ms_noise_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_dp_ks_ms_pfail_gpu(meta_params: MetaParameters) {
    let mut ap_params = meta_params.compute_parameters;
    let (pfail_test_meta, params) = {
        let original_message_modulus = ap_params.message_modulus();
        let original_carry_modulus = ap_params.carry_modulus();

        // For now only allow 2_2 parameters, and see later for heuristics to use
        assert_eq!(original_message_modulus.0, 4);
        assert_eq!(original_carry_modulus.0, 4);

        // Update parameters to fail more frequently by inflating the carry modulus, allows to keep
        // the max multiplication without risks of message overflow
        let (original_pfail_and_precision, new_expected_pfail_and_precision) =
            update_ap_params_for_pfail(
                &mut ap_params,
                original_message_modulus,
                CarryModulus(1 << 5),
            );

        let pfail_test_meta = if should_run_short_pfail_tests_debug() {
            let expected_fails = 200;
            PfailTestMeta::new_with_desired_expected_fails(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                expected_fails,
            )
        } else {
            let total_runs = 1_000_000;
            PfailTestMeta::new_with_total_runs(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                total_runs,
            )
        };

        (pfail_test_meta, ap_params)
    };

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let max_scalar_mul = cuda_sks.max_noise_level.get();
    let br_input_modulus_log = cuda_sks.br_input_modulus_log();
    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let chunk_size = 8;
    let vec_local_streams = (0..chunk_size)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();
    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .collect::<Vec<_>>()
        .chunks(chunk_size)
        .flat_map(|chunk| {
            chunk
                .into_par_iter()
                .map(|i| {
                    let local_streams = &vec_local_streams[*i as usize % chunk_size];
                    let after_ms_decryption_result = encrypt_dp_ks_any_ms_pfail_helper_gpu(
                        params,
                        &cks.key,
                        &cuda_sks,
                        0,
                        max_scalar_mul,
                        br_input_modulus_log,
                        local_streams,
                    );
                    after_ms_decryption_result.failure_as_f64()
                })
                .collect::<Vec<_>>()
        })
        .sum();
    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_gpu_parameterized_test!(noise_check_encrypt_dp_ks_ms_pfail_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
