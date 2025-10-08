use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{CudaSideResources, CudaStreams};
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::CudaBlockInfo;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::IntegerCiphertext;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::AtomicPatternParameters;
use crate::shortint::server_key::tests::noise_distribution::should_use_single_key_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    DecryptionAndNoiseResult, NoiseSample,
};
use rayon::prelude::*;

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::noise_simulation::CudaDynLwe;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::{unchecked_small_scalar_mul_integer_async, CastInto, CudaVec};
use crate::integer::server_key::ServerKey;
use crate::integer::CompressedServerKey;
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::server_key::tests::noise_distribution::dp_ks_ms::{
    dp_ks_any_ms, dp_ks_any_ms_classic_pbs,
};
use crate::shortint::server_key::tests::noise_distribution::should_run_short_pfail_tests_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationDriftTechniqueKey, NoiseSimulationLwe,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    PfailTestMeta, PfailTestResult,
};
use crate::shortint::{ClientKey, ShortintParameterSet};
use itertools::Itertools;

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint
fn sanity_check_encrypt_dp_ks_pbs_gpu<P>(params: P)
where
    P: Into<AtomicPatternParameters> + Copy,
{
    let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let noise_simulation_modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = sks.key.br_input_modulus_log();
    let _expected_average_after_ms = noise_simulation_modulus_switch_config
        .expected_average_after_ms(atomic_params.polynomial_size());

    let max_scalar_mul = sks.key.max_noise_level.get();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&cuda_sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };
    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: crate::shortint::parameters::AtomicPatternKind::Standard(
            crate::shortint::parameters::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let side_resources = CudaSideResources::new(&streams, block_info);
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
    for _ in 0..10 {
        let ct_input = cks.key.encrypt(0);
        let cloned_ct_input = ct_input.clone();
        let radix_ct_input = crate::integer::RadixCiphertext::from_blocks(vec![ct_input]);
        let d_ct_input =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct_input, &streams);
        let gpu_sample_input = CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks);

        let (_input, _after_dp, _after_ks, _before_ms, _after_ms, after_pbs) =
            dp_ks_any_ms_classic_pbs(
                gpu_sample_input,
                max_scalar_mul,
                &cuda_sks,
                noise_simulation_modulus_switch_config,
                drift_key,
                &cuda_sks,
                br_input_modulus_log,
                &d_accumulator,
                &side_resources,
            );

        let after_pbs_list = after_pbs.as_lwe_64().to_lwe_ciphertext_list(&streams);
        let after_pbs_ct = LweCiphertext::from_container(
            after_pbs_list.clone().into_container(),
            after_pbs_list.ciphertext_modulus(),
        );

        let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![cloned_ct_input]);
        let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct, &streams);

        unsafe {
            unchecked_small_scalar_mul_integer_async(
                &streams,
                &mut d_ct.ciphertext,
                max_scalar_mul,
                atomic_params.message_modulus(),
                atomic_params.carry_modulus(),
            );
        }
        streams.synchronize();

        let mut after_pbs_shortint_ct: CudaUnsignedRadixCiphertext =
            cuda_sks.create_trivial_zero_radix(1, &streams);
        unsafe {
            cuda_sks.apply_lookup_table_async(
                &mut after_pbs_shortint_ct.ciphertext,
                &d_ct.ciphertext,
                &id_lut,
                0..1,
                &streams,
            );
        }
        streams.synchronize();

        let shortint_res_list = after_pbs_shortint_ct
            .ciphertext
            .d_blocks
            .to_lwe_ciphertext_list(&streams);
        let shortint_res_ct = LweCiphertext::from_container(
            shortint_res_list.clone().into_container(),
            shortint_res_list.ciphertext_modulus(),
        );
        assert_eq!(after_pbs_ct.as_view(), shortint_res_ct.as_view());
    }
}

#[cfg(feature = "gpu")]
create_gpu_parameterized_test!(sanity_check_encrypt_dp_ks_pbs_gpu {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

use crate::shortint::CarryModulus;
fn encrypt_dp_ks_any_ms_inner_helper_gpu(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
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
    let thread_sks: crate::integer::ServerKey;
    let thread_cuda_sks: CudaServerKey;

    let (cks, sks, cuda_sks) = if should_use_single_key_debug() {
        (single_cks, single_sks, single_cuda_sks)
    } else {
        let block_params: ShortintParameterSet = params.into();
        thread_cks = crate::integer::ClientKey::new(block_params);
        let thread_compressed_server_key =
            CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
        thread_sks = thread_compressed_server_key.decompress();
        thread_cuda_sks =
            CudaServerKey::decompress_from_cpu(&thread_compressed_server_key, streams);
        (&thread_cks.key, &thread_sks, &thread_cuda_sks)
    };
    let noise_simulation_modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(cuda_sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let ct_input = cks.encrypt(msg);
    let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct_input.ct, streams);
    let gpu_sample_input = CudaDynLwe::U64(d_ct_input);
    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::parameters::AtomicPatternKind::Standard(
            crate::shortint::parameters::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let mut side_resources = CudaSideResources::new(streams, block_info);

    let (input_gpu, after_dp_gpu, after_ks_gpu, after_drift_gpu, after_ms_gpu) = dp_ks_any_ms(
        gpu_sample_input,
        scalar_for_multiplication,
        cuda_sks,
        noise_simulation_modulus_switch_config,
        drift_key,
        br_input_modulus_log,
        &mut side_resources,
    );
    side_resources.streams.synchronize();

    let input_list = input_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let input_ct = LweCiphertext::from_container(
        input_list.clone().into_container(),
        input_list.ciphertext_modulus(),
    );
    // Convert back to CPU for decryption and noise analysis
    // I should wrap up this in a function
    let input = DynLwe::U64(input_ct);
    let after_dp_list = after_dp_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let after_dp_ct = LweCiphertext::from_container(
        after_dp_list.clone().into_container(),
        after_dp_list.ciphertext_modulus(),
    );
    let after_dp = DynLwe::U64(after_dp_ct);
    let after_ks_list = after_ks_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let after_ks_ct = LweCiphertext::from_container(
        after_ks_list.clone().into_container(),
        after_ks_list.ciphertext_modulus(),
    );
    let after_ks = DynLwe::U64(after_ks_ct);
    let after_ms_list = after_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let after_ms_ct = LweCiphertext::from_container(
        after_ms_list.clone().into_container(),
        after_ms_list.ciphertext_modulus(),
    );
    let after_ms = DynLwe::U64(after_ms_ct);

    let before_ms_gpu: &CudaDynLwe = after_drift_gpu.as_ref().unwrap_or(&after_ks_gpu);
    let before_ms_list = before_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let before_ms_ct = LweCiphertext::from_container(
        before_ms_list.clone().into_container(),
        before_ms_list.ciphertext_modulus(),
    );
    let before_ms = DynLwe::U64(before_ms_ct);

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new_from_lwe(
                &input.as_lwe_64(),
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_dp.as_lwe_64(),
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_ks.as_lwe_64(),
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &before_ms.as_lwe_64(),
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_ms.as_lwe_64(),
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
    single_sks: &ServerKey,
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
        single_sks,
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
    single_sks: &ServerKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> DecryptionAndNoiseResult {
    let (_input, _before_ms, _after_ks, after_ms, _after_pbs) =
        encrypt_dp_ks_any_ms_inner_helper_gpu(
            params,
            single_cks,
            single_sks,
            single_cuda_sks,
            msg,
            scalar_for_multiplication,
            br_input_modulus_log,
            streams,
        );

    after_ms
}

/// GPU version of the noise checking test
fn noise_check_encrypt_dp_ks_ms_noise_gpu<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let noise_simulation_modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = sks.key.br_input_modulus_log();
    let expected_average_after_ms =
        noise_simulation_modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    let drift_key = match &sks.key.atomic_pattern {
        // TODO manage key checks directly on the noise simulations objects
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key));

            let drift_key = standard_atomic_pattern_server_key
                .bootstrapping_key
                .modulus_switch_configuration()
                .unwrap()
                .modulus_switch_noise_reduction_key();

            match (drift_key, noise_simulation_drift_key) {
                (Some(drift_key), Some(noise_simulation_drift_key)) => {
                    assert!(noise_simulation_drift_key.matches_actual_drift_key(drift_key))
                }
                (None, None) => (),
                _ => panic!("Inconsistent drift_key configuration"),
            }

            match noise_simulation_modulus_switch_config {
                NoiseSimulationModulusSwitchConfig::Standard => None,
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&cuda_sks),
                NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
            }
        }
        _ => unimplemented!(),
    };
    let max_scalar_mul = sks.key.max_noise_level.get();

    let (_input_sim, _after_dp_sim, _after_ks_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks.key, 0);
        dp_ks_any_ms(
            noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config,
            noise_simulation_drift_key.as_ref(),
            br_input_modulus_log,
            &(),
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
            degree: crate::shortint::parameters::Degree::new(1),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            atomic_pattern: crate::shortint::parameters::AtomicPatternKind::Standard(
                crate::shortint::parameters::PBSOrder::KeyswitchBootstrap,
            ),
            noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
        };
        let mut side_resources = CudaSideResources::new(&streams, block_info);

        let (_input, _after_dp, _after_ks, _after_drift, after_ms) = dp_ks_any_ms(
            gpu_sample_input,
            max_scalar_mul,
            &cuda_sks,
            noise_simulation_modulus_switch_config,
            drift_key,
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
    let num_streams = 16;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(0)))
        .collect::<Vec<_>>();

    let sample_count_per_msg = 1000usize;
    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .into_par_iter()
            .map(|index| {
                let stream_index = index % num_streams;
                let local_streams = &vec_local_streams[stream_index];
                let (_input, _after_dp, _after_ks, before_ms, after_ms) =
                    encrypt_dp_ks_any_ms_noise_helper_gpu(
                        params,
                        &cks.key,
                        &sks,
                        &cuda_sks,
                        0,
                        max_scalar_mul,
                        br_input_modulus_log,
                        local_streams,
                    );
                (before_ms.value, after_ms.value)
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
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn noise_check_encrypt_dp_ks_ms_pfail_gpu<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let (pfail_test_meta, params) = {
        let mut ap_params: AtomicPatternParameters = params.into();

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
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let max_scalar_mul = sks.key.max_noise_level.get();
    let br_input_modulus_log = sks.key.br_input_modulus_log();
    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let num_streams = 16;
    let vec_local_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(0)))
        .collect::<Vec<_>>();
    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_iter()
        .map(|index| {
            let stream_index = index % num_streams;
            let local_streams = &vec_local_streams[stream_index as usize];
            let after_ms_decryption_result = encrypt_dp_ks_any_ms_pfail_helper_gpu(
                params,
                &cks.key,
                &sks,
                &cuda_sks,
                0,
                max_scalar_mul,
                br_input_modulus_log,
                local_streams,
            );
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_gpu_parameterized_test!(noise_check_encrypt_dp_ks_ms_pfail_gpu {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
