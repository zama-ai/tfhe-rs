use super::utils::noise_simulation::{CudaDynLwe, CudaSideResources};
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLweBootstrapResult, LweClassicFftBootstrap,
};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_stringified_test;
use crate::integer::gpu::server_key::radix::CudaBlockInfo;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::gpu::unchecked_small_scalar_mul_integer;
use crate::integer::{CompressedServerKey, IntegerCiphertext};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, MetaParameters, Variance};
use crate::shortint::server_key::tests::noise_distribution::br_dp_ks_ms::br_dp_ks_any_ms;
use crate::shortint::server_key::tests::noise_distribution::should_use_single_key_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    NoiseSimulationGenericBootstrapKey, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweKeyswitchKey, NoiseSimulationModulus,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::{
    write_empty_json_file, write_to_json_file, DpKsMsNoiseCheckResult, TestResult,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::this_function_name;

use crate::shortint::server_key::tests::noise_distribution::should_run_short_pfail_tests_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulusSwitchConfig;
use crate::shortint::{CarryModulus, Ciphertext, ClientKey, ShortintParameterSet};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_br_dp_ks_pbs_gpu(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let atomic_params = meta_params.compute_parameters;
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = cuda_sks.br_input_modulus_log();
    let max_scalar_mul = cuda_sks.max_noise_level.get();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(atomic_params.message_modulus().0 - 1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: atomic_params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let mut cuda_side_resources = CudaSideResources::new(&streams, block_info);

    type SanityVec = (LweCiphertext<Vec<u64>>, LweCiphertext<Vec<u64>>);
    let mut results: Vec<SanityVec> = Vec::new();

    for _ in 0..10 {
        let input_zero_as_lwe = cks
            .key
            .encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0);

        let d_ct_input =
            CudaLweCiphertextList::from_lwe_ciphertext(&input_zero_as_lwe.as_lwe_64(), &streams);
        let gpu_sample_input = CudaDynLwe::U64(d_ct_input);

        let (_input, d_input_pbs_result, _after_dp, _ks_result, _drift_technique_result, ms_result) =
            br_dp_ks_any_ms(
                gpu_sample_input,
                &cuda_sks,
                max_scalar_mul,
                &cuda_sks,
                modulus_switch_config,
                &d_accumulator,
                br_input_modulus_log,
                &mut cuda_side_resources,
            );

        let mut output_pbs_result =
            d_accumulator.allocate_lwe_bootstrap_result(&mut cuda_side_resources);
        cuda_sks.lwe_classic_fft_pbs(
            &ms_result,
            &mut output_pbs_result,
            &d_accumulator,
            &mut cuda_side_resources,
        );

        let after_pbs_ct = output_pbs_result.as_ct_64_cpu(&cuda_side_resources.streams);
        let input_pbs_result = d_input_pbs_result.as_ct_64_cpu(&cuda_side_resources.streams);

        // Shortint APIs are not granular enough to compare ciphertexts at the MS level
        // and inject arbitrary LWEs as input to the blind rotate step of the PBS.
        // So we start with the output of the input PBS from our test case and finish after
        // the second PBS and not the MS from our dedicated sanity function, which are
        // boundaries that are easily reached with shortint.
        // We don't want to use that dedicated function in statistical tests as it computes
        // 2 PBSes instead of one, the output of the seoncd PBS being of no interest for
        // noise measurement here.

        let shortint_res = Ciphertext::new(
            input_pbs_result,
            id_lut.degree,
            NoiseLevel::NOMINAL,
            cuda_sks.message_modulus,
            cuda_sks.carry_modulus,
            atomic_params.atomic_pattern(),
        );

        let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![shortint_res]);
        let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &radix_ct,
            &cuda_side_resources.streams,
        );

        unchecked_small_scalar_mul_integer(
            &cuda_side_resources.streams,
            &mut d_ct.ciphertext,
            max_scalar_mul,
            atomic_params.message_modulus(),
            atomic_params.carry_modulus(),
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

        results.push((after_pbs_ct, shortint_res_ct));
    }

    let res_cond = results
        .iter()
        .all(|(lhs, rhs)| lhs.as_view() == rhs.as_view());

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        res_cond,
        None,
        TestResult::Empty {},
    )
    .unwrap();

    // We check each step to preserve failure details and print the invalid case if one occurs
    for (after_pbs_ct, shortint_res_ct) in results.iter() {
        assert_eq!(after_pbs_ct.as_view(), shortint_res_ct.as_view());
    }
}

create_gpu_parameterized_stringified_test!(sanity_check_encrypt_br_dp_ks_pbs_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn encrypt_br_dp_ks_any_ms_inner_helper_gpu(
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
    let ct = cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0);

    let d_ct_lwe = CudaLweCiphertextList::from_lwe_ciphertext(&ct.as_lwe_64(), streams);
    let d_ct = CudaDynLwe::U64(d_ct_lwe);

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let mut cuda_side_resources = CudaSideResources::new(streams, block_info);

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, streams);

    let (input_gpu, after_br_gpu, after_dp_gpu, after_ks_gpu, after_drift_gpu, after_ms_gpu) =
        br_dp_ks_any_ms(
            d_ct,
            cuda_sks,
            scalar_for_multiplication,
            cuda_sks,
            modulus_switch_config,
            &d_accumulator,
            br_input_modulus_log,
            &mut cuda_side_resources,
        );

    let input_ct = input_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_br_ct = after_br_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_dp_ct = after_dp_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_ks_ct = after_ks_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let before_ms_gpu: &CudaDynLwe = after_drift_gpu.as_ref().unwrap_or(&after_ks_gpu);
    let before_ms_ct = before_ms_gpu.as_ct_64_cpu(&cuda_side_resources.streams);
    let after_ms_ct = after_ms_gpu.as_ct_64_cpu(&cuda_side_resources.streams);

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new_from_lwe(
                &input_ct,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_br_ct,
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

fn encrypt_br_dp_ks_any_ms_noise_helper_gpu(
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
    NoiseSample,
) {
    let (input, after_br, after_dp, after_ks, before_ms, after_ms) =
        encrypt_br_dp_ks_any_ms_inner_helper_gpu(
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
        after_br
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

fn encrypt_br_dp_ks_any_ms_pfail_helper_gpu(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> DecryptionAndNoiseResult {
    let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) =
        encrypt_br_dp_ks_any_ms_inner_helper_gpu(
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

fn noise_check_encrypt_br_dp_ks_ms_noise(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let params: AtomicPatternParameters = meta_params.compute_parameters;

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk =
        NoiseSimulationGenericBootstrapKey::new_from_atomic_pattern_parameters(params);
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

    let (_input_sim, _after_br_sim, _after_dp_sim, _after_ks_sim, _after_drift_sim, after_ms_sim) = {
        // Noiseless LWE already mod switched is the input of the AP for testing
        let noise_simulation = NoiseSimulationLwe::new(
            noise_simulation_bsk.input_lwe_dimension(),
            Variance(0.0),
            NoiseSimulationModulus::Other(1 << br_input_modulus_log.0),
        );
        let noise_simulation_accumulator = NoiseSimulationGlwe::new(
            noise_simulation_bsk.output_glwe_size().to_glwe_dimension(),
            noise_simulation_bsk.output_polynomial_size(),
            Variance(0.0),
            noise_simulation_bsk.modulus(),
        );
        br_dp_ks_any_ms(
            noise_simulation,
            &noise_simulation_bsk,
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_accumulator,
            br_input_modulus_log,
            &mut (),
        )
    };

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);
    let sample_input = cks
        .key
        .encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0);

    let d_ct_input =
        CudaLweCiphertextList::from_lwe_ciphertext(&sample_input.as_lwe_64(), &streams);
    let gpu_sample_input = CudaDynLwe::U64(d_ct_input);

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut side_resources = CudaSideResources::new(&streams, block_info);

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) = br_dp_ks_any_ms(
            gpu_sample_input,
            &cuda_sks,
            max_scalar_mul,
            &cuda_sks,
            modulus_switch_config_gpu,
            &d_accumulator,
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
                        let (_input, _after_br, _after_dp, _after_ks, before_ms, after_ms) =
                            encrypt_br_dp_ks_any_ms_noise_helper_gpu(
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

    let (after_ms_is_ok, bounded_variance_measurement, bounded_mean_measurement) =
        mean_and_variance_check(
            &noise_samples_after_ms,
            "after_ms",
            expected_average_after_ms,
            after_ms_sim.variance(),
            params.lwe_noise_distribution(),
            after_ms_sim.lwe_dimension(),
            after_ms_sim.modulus().as_f64(),
        );

    let before_ms_normality_valid = before_ms_normality.null_hypothesis_is_valid;

    let sanity_check_valid = before_ms_normality_valid && after_ms_is_ok;

    let noise_check = TestResult::DpKsMsNoiseCheckResult(Box::new(DpKsMsNoiseCheckResult::new(
        bounded_variance_measurement,
        bounded_mean_measurement,
        before_ms_normality_valid,
    )));

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        sanity_check_valid,
        None,
        noise_check,
    )
    .unwrap();

    assert!(sanity_check_valid);
}

create_gpu_parameterized_stringified_test!(noise_check_encrypt_br_dp_ks_ms_noise {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_br_dp_ks_ms_pfail_gpu(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (pfail_test_meta, params) = {
        let mut ap_params: AtomicPatternParameters = meta_params.compute_parameters;

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
                    let after_ms_decryption_result = encrypt_br_dp_ks_any_ms_pfail_helper_gpu(
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

    pfail_check(
        &pfail_test_meta,
        test_result,
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    );
}

create_gpu_parameterized_stringified_test!(noise_check_encrypt_br_dp_ks_ms_pfail_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
