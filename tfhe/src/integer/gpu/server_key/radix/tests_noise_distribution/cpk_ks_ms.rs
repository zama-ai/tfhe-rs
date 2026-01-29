use crate::integer::gpu::ciphertext::compact_list::CudaFlattenedVecCompactCiphertextList;

use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_stringified_test;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, MetaParameters, ShortintCompactCiphertextListCastingMode,
    ShortintKeySwitchingParameters,
};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, DynModSwitchedLwe, NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey,
    NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::{
    write_empty_json_file, write_to_json_file, NoiseCheckWithNormalityCheck, TestResult,
};
use crate::this_function_name;
use crate::integer::gpu::server_key::radix::LweCiphertextList;
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
use rayon::prelude::*;
use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::{ClientKey, CompressedServerKey};
use crate::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use super::utils::noise_simulation::{CudaDynLwe, CudaSideResources};
use crate::shortint::ShortintParameterSet;
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::shortint::server_key::tests::noise_distribution::cpk_ks_ms::cpk_ks_any_ms;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::lwe_programmable_bootstrap::LweClassicFftBootstrap;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::lwe_programmable_bootstrap::AllocateLweBootstrapResult;
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::{CompactPublicKey, CompactPrivateKey};
use crate::integer::ciphertext::DataKind;
use std::num::NonZeroUsize;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::key_switching_test_utils::new_key_switching_key_for_pfail_test;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_any_ms_inner_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_cuda_ksk: &CudaKeySwitchingKey<'_>,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let mut engine = ShortintEngine::new();
    let thread_cpk_private_key;
    let thread_cpk;
    let thread_cuda_ksk;
    let thread_cks;
    let thread_sks;
    let thread_cuda_sks;
    let thread_cuda_ksk_material;
    let (cpk_private_key, cpk, cuda_ksk, cks, cuda_sks) = if should_use_single_key_debug() {
        (
            single_cpk_private_key,
            single_cpk,
            single_cuda_ksk,
            single_cks,
            single_cuda_sks,
        )
    } else {
        thread_cpk_private_key = CompactPrivateKey::new(cpk_params);
        thread_cpk = CompactPublicKey::new(&thread_cpk_private_key);

        let block_params: ShortintParameterSet = params.into();
        thread_cks = crate::integer::ClientKey::new(block_params);
        let compressed_server_key =
            CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
        thread_sks = compressed_server_key.decompress();
        thread_cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, streams);
        let ksk = new_key_switching_key_for_pfail_test(
            (&thread_cpk_private_key, None),
            (&thread_cks, &thread_sks),
            ksk_ds_params,
        );
        thread_cuda_ksk_material =
            CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, streams);
        thread_cuda_ksk = CudaKeySwitchingKey::from_cuda_key_switching_key_material(
            &thread_cuda_ksk_material,
            &thread_cuda_sks,
        );

        (
            &thread_cpk_private_key,
            &thread_cpk,
            &thread_cuda_ksk,
            &thread_cks,
            &thread_cuda_sks,
        )
    };

    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(streams, cuda_block_info);
    let ct = {
        let compact_list = cpk.key.encrypt_iter_with_modulus_with_engine(
            core::iter::once(msg),
            cpk.key.parameters.message_modulus.0,
            &mut engine,
        );

        let num_blocks = 1usize;

        let data_info = vec![DataKind::Unsigned(NonZeroUsize::new(num_blocks).unwrap())];
        let cuda_casting_compact_list =
            CudaFlattenedVecCompactCiphertextList::from_vec_shortint_compact_ciphertext_list(
                vec![compact_list],
                data_info,
                &cuda_side_resources.streams,
            );
        let cuda_compact_list_expander = cuda_casting_compact_list
            .expand(
                cuda_ksk,
                crate::integer::gpu::ZKType::NoCasting,
                &cuda_side_resources.streams,
            )
            .unwrap();

        let cuda_expanded_ct: CudaUnsignedRadixCiphertext = cuda_compact_list_expander
            .get(0usize, &cuda_side_resources.streams)
            .unwrap()
            .unwrap();

        CudaDynLwe::U64(cuda_expanded_ct.ciphertext.d_blocks)
    };

    let (input_gpu, after_ks_ds_gpu, after_drift_gpu, after_ms_gpu) = cpk_ks_any_ms(
        ct,
        cuda_ksk,
        modulus_switch_config,
        br_input_modulus_log,
        &mut cuda_side_resources,
    );

    let input_ct = input_gpu.as_ct_64_cpu(streams);
    let after_ks_ds_ct = after_ks_ds_gpu.as_ct_64_cpu(streams);
    let before_ms_gpu: &CudaDynLwe = after_drift_gpu.as_ref().unwrap_or(&after_ks_ds_gpu);
    let before_ms_ct = before_ms_gpu.as_ct_64_cpu(streams);

    let after_ms_ct = after_ms_gpu.as_ct_64_cpu(streams);
    let cpk_lwe_secret_key_dyn = cpk_private_key.key.lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.key.small_lwe_secret_key_as_dyn();

    (
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &DynLwe::U64(input_ct),
            &cpk_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &DynLwe::U64(after_ks_ds_ct),
            &small_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &DynLwe::U64(before_ms_ct),
            &small_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
            &DynModSwitchedLwe::ModSwitchedLwe(DynLwe::U64(after_ms_ct)),
            &small_lwe_secret_key_dyn,
            msg,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_any_ms_noise_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_cuda_ksk_ds: &CudaKeySwitchingKey<'_>,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (NoiseSample, NoiseSample, NoiseSample, NoiseSample) {
    let (input, after_ks_ds, before_ms, after_ms) = cpk_ks_any_ms_inner_helper_gpu(
        params,
        cpk_params,
        ksk_ds_params,
        single_cpk_private_key,
        single_cpk,
        single_cuda_ksk_ds,
        single_cks,
        single_cuda_sks,
        msg,
        br_input_modulus_log,
        streams,
    );

    (
        input
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ks_ds
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_any_ms_pfail_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_cuda_ksk_ds: &CudaKeySwitchingKey<'_>,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> DecryptionAndNoiseResult {
    let (_input, _after_ks_ds, _before_ms, after_ms) = cpk_ks_any_ms_inner_helper_gpu(
        params,
        cpk_params,
        ksk_ds_params,
        single_cpk_private_key,
        single_cpk,
        single_cuda_ksk_ds,
        single_cks,
        single_cuda_sks,
        msg,
        br_input_modulus_log,
        streams,
    );

    after_ms
}

fn noise_check_encrypt_cpk_ks_ms_noise_gpu(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, ksk_ds_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            cpk_params
        };

        (compute_params, cpk_params, dedicated_cpk_params.ksk_params)
    };
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let ksk = KeySwitchingKey::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_ds =
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(cpk_params, ksk_ds_params, params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);

    let modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let cuda_modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.key.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks.key));
    assert!(noise_simulation_ksk_ds.matches_actual_shortint_keyswitching_key(&ksk.key.as_view()));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));

    let (_input_sim, _after_ks_ds_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation_input = NoiseSimulationLwe::encrypt_with_cpk(&cpk.key);
        cpk_ks_any_ms(
            noise_simulation_input,
            &noise_simulation_ksk_ds,
            noise_simulation_modulus_switch_config.as_ref(),
            compute_br_input_modulus_log,
            &mut (),
        )
    };

    let sample_input = {
        let compact_list = cpk.key.encrypt_slice(&[0]);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };
    let d_ct_input =
        CudaLweCiphertextList::from_lwe_ciphertext(&sample_input.as_lwe_64(), &streams);
    let gpu_sample_input = CudaDynLwe::U64(d_ct_input);

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(&streams, cuda_block_info);
    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_ks_ds, _before_ms, after_ms) = cpk_ks_any_ms(
            gpu_sample_input,
            &cuda_ksk,
            cuda_modulus_switch_config,
            compute_br_input_modulus_log,
            &mut cuda_side_resources,
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
                    .iter()
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &vec_local_streams[*i % chunk_size];
                        let (_input, _after_ks_ds, before_ms, after_ms) =
                            cpk_ks_any_ms_noise_helper_gpu(
                                params,
                                cpk_params,
                                ksk_ds_params,
                                &cpk_private_key,
                                &cpk,
                                &cuda_ksk,
                                &cks,
                                &cuda_sks,
                                0,
                                compute_br_input_modulus_log,
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

    let noise_check =
        TestResult::NoiseCheckWithNormalityCheck(Box::new(NoiseCheckWithNormalityCheck::new(
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

create_gpu_parameterized_stringified_test!(noise_check_encrypt_cpk_ks_ms_noise_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_cpk_ks_ms_pfail_gpu(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, ksk_ds_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            cpk_params
        };

        (compute_params, cpk_params, dedicated_cpk_params.ksk_params)
    };

    let (pfail_test_meta, params) = {
        let mut ap_params = params;

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
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let ksk =
        new_key_switching_key_for_pfail_test((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);

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
                .iter()
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|i| {
                    let local_stream = &vec_local_streams[*i as usize % chunk_size];
                    let after_ms_decryption_result = cpk_ks_any_ms_pfail_helper_gpu(
                        params,
                        cpk_params,
                        ksk_ds_params,
                        &cpk_private_key,
                        &cpk,
                        &cuda_ksk,
                        &cks,
                        &cuda_sks,
                        0,
                        sks.key.br_input_modulus_log(),
                        local_stream,
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

create_gpu_parameterized_stringified_test!(noise_check_encrypt_cpk_ks_ms_pfail_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn sanity_check_encrypt_cpk_ks_ms_pbs_gpu(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, ksk_ds_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let (cpk_params, orig_cast_mode) = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            let orig_cast_mode = cpk_params.expansion_kind;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            (cpk_params, orig_cast_mode)
        };

        assert!(matches!(
            orig_cast_mode,
            CompactCiphertextListExpansionKind::RequiresCasting
        ));

        (compute_params, cpk_params, dedicated_cpk_params.ksk_params)
    };
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);
    let ksk = KeySwitchingKey::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);
    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.key.br_input_modulus_log();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(&streams, cuda_block_info);

    type SanityVec = (LweCiphertextList<Vec<u64>>, LweCiphertextList<Vec<u64>>);
    let mut results: Vec<SanityVec> = Vec::new();

    for _ in 0..10 {
        let (gpu_sample_input, shortint_res) = {
            let mut engine = ShortintEngine::new();
            let no_casting_compact_list = cpk.key.encrypt_iter_with_modulus_with_engine(
                core::iter::once(0),
                cpk.key.parameters.message_modulus.0,
                &mut engine,
            );

            let num_blocks = 1usize;
            let data_info = vec![DataKind::Unsigned(NonZeroUsize::new(num_blocks).unwrap())];
            //This is for the ap
            let cuda_no_casting_compact_list =
                CudaFlattenedVecCompactCiphertextList::from_vec_shortint_compact_ciphertext_list(
                    vec![no_casting_compact_list.clone()],
                    data_info,
                    &cuda_side_resources.streams,
                );

            //This is for the verification
            let cuda_casting_compact_list =
                cuda_no_casting_compact_list.duplicate(&cuda_side_resources.streams);

            let cuda_no_casting_compact_list_expander = cuda_no_casting_compact_list
                .expand(
                    &cuda_ksk,
                    crate::integer::gpu::ZKType::NoCasting,
                    &cuda_side_resources.streams,
                )
                .unwrap();

            let cuda_ap_input_expanded: CudaUnsignedRadixCiphertext =
                cuda_no_casting_compact_list_expander
                    .get(0usize, &cuda_side_resources.streams)
                    .unwrap()
                    .unwrap();

            let cuda_casting_compact_list_expander = cuda_casting_compact_list
                .expand(
                    &cuda_ksk,
                    crate::integer::gpu::ZKType::SanityCheck,
                    &cuda_side_resources.streams,
                )
                .unwrap();

            let cuda_int_res: CudaUnsignedRadixCiphertext = cuda_casting_compact_list_expander
                .get(0usize, &cuda_side_resources.streams)
                .unwrap()
                .unwrap();

            (
                CudaDynLwe::U64(
                    cuda_ap_input_expanded
                        .ciphertext
                        .d_blocks
                        .duplicate(&cuda_side_resources.streams),
                ),
                cuda_int_res
                    .ciphertext
                    .d_blocks
                    .to_lwe_ciphertext_list(&cuda_side_resources.streams),
            )
        };

        let (_input, _after_ks, _before_ms, after_ms) = cpk_ks_any_ms(
            gpu_sample_input,
            &cuda_ksk,
            modulus_switch_config,
            compute_br_input_modulus_log,
            &mut cuda_side_resources,
        );

        // Complete the AP by computing the PBS to match shortint
        let mut pbs_result = d_accumulator.allocate_lwe_bootstrap_result(&mut cuda_side_resources);
        cuda_sks.lwe_classic_fft_pbs(
            &after_ms,
            &mut pbs_result,
            &d_accumulator,
            &mut cuda_side_resources,
        );

        let pbs_result_list = pbs_result
            .as_lwe_64()
            .to_lwe_ciphertext_list(&cuda_side_resources.streams);

        results.push((pbs_result_list.clone(), shortint_res.clone()));
    }

    let res_cond = results.iter().all(|(lhs, rhs)| lhs == rhs);

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
    for (pbs_result_list, shortint_res) in results.iter() {
        assert_eq!(pbs_result_list, shortint_res);
    }
}

create_gpu_parameterized_stringified_test!(sanity_check_encrypt_cpk_ks_ms_pbs_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
