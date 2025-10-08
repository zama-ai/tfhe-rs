use super::utils::noise_simulation::CudaDynLwe;
use crate::core_crypto::commons::parameters::{CiphertextModulus, CiphertextModulusLog};
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{CudaSideResources, CudaStreams};
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::server_key::radix::CudaBlockInfo;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::gpu::unchecked_small_scalar_mul_integer_async;
use crate::integer::server_key::ServerKey;
use crate::integer::{CompressedServerKey, IntegerCiphertext};
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternServerKey};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, Variance};
use crate::shortint::server_key::tests::noise_distribution::br_dp_ks_ms::{
    br_dp_ks_any_ms, br_dp_ks_any_ms_pbs,
};
use crate::shortint::server_key::tests::noise_distribution::should_use_single_key_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationDriftTechniqueKey, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweFourierBsk, NoiseSimulationLweKeyswitchKey, NoiseSimulationModulus,
    NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    encrypt_new_noiseless_lwe, mean_and_variance_check, normality_check, pfail_check,
    update_ap_params_for_pfail, DecryptionAndNoiseResult, NoiseSample, PfailTestMeta,
    PfailTestResult,
};

use crate::shortint::server_key::tests::noise_distribution::should_run_short_pfail_tests_debug;
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::{CarryModulus, Ciphertext, ClientKey, ShortintParameterSet};
use itertools::Itertools;
/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_br_dp_ks_pbs_gpu<P>(params: P)
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

    let max_scalar_mul = sks.key.max_noise_level.get();

    let ms_ciphertext_modulus: CiphertextModulus<u64> =
        CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&cuda_sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let small_lwe_sk = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            standard_atomic_pattern_client_key.lwe_secret_key.as_view()
        }
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
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
    let ms_encoding = ShortintEncoding {
        ciphertext_modulus: ms_ciphertext_modulus,
        message_modulus: sks.message_modulus(),
        carry_modulus: sks.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let mut side_resources = CudaSideResources::new(&streams, block_info);

    for _ in 0..10 {
        let input_zero_as_lwe: LweCiphertext<Vec<u64>> =
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_new_noiseless_lwe(
                    &small_lwe_sk,
                    ms_ciphertext_modulus,
                    0,
                    &ms_encoding,
                    &mut engine.encryption_generator,
                )
            });

        let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&input_zero_as_lwe, &streams);
        let gpu_sample_input = CudaDynLwe::U64(d_ct_input);

        let (
            _input,
            d_input_pbs_result,
            _after_dp,
            _ks_result,
            _drift_technique_result,
            _ms_result,
            output_pbs_result,
        ) = br_dp_ks_any_ms_pbs(
            gpu_sample_input,
            &cuda_sks,
            max_scalar_mul,
            &cuda_sks,
            noise_simulation_modulus_switch_config,
            drift_key,
            &d_accumulator,
            br_input_modulus_log,
            &mut side_resources,
        );

        let after_pbs_list = output_pbs_result
            .as_lwe_64()
            .to_lwe_ciphertext_list(&streams);
        let after_pbs_ct = LweCiphertext::from_container(
            after_pbs_list.clone().into_container(),
            after_pbs_list.ciphertext_modulus(),
        );
        let input_pbs_result_list = d_input_pbs_result
            .as_lwe_64()
            .to_lwe_ciphertext_list(&streams);
        let input_pbs_result = LweCiphertext::from_container(
            input_pbs_result_list.clone().into_container(),
            input_pbs_result_list.ciphertext_modulus(),
        );
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
            sks.key.message_modulus,
            sks.key.carry_modulus,
            sks.key.atomic_pattern.kind(),
        );

        let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![shortint_res]);
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
create_gpu_parameterized_test!(sanity_check_encrypt_br_dp_ks_pbs_gpu {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn encrypt_br_dp_ks_any_ms_inner_helper_gpu(
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

    let ct = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_new_noiseless_lwe(
                    &standard_atomic_pattern_client_key.lwe_secret_key,
                    CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap(),
                    0,
                    &sks.key.encoding(PaddingBit::Yes),
                    &mut engine.encryption_generator,
                )
            })
        }
        AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => todo!(),
    };
    let d_ct_lwe = CudaLweCiphertextList::from_lwe_ciphertext(&ct, streams);
    let d_ct = CudaDynLwe::U64(d_ct_lwe);

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::parameters::AtomicPatternKind::Standard(
            crate::shortint::parameters::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };

    let side_resources = CudaSideResources::new(streams, block_info);

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, streams);

    let (input_gpu, after_br_gpu, after_dp_gpu, after_ks_gpu, after_drift_gpu, after_ms_gpu) =
        br_dp_ks_any_ms(
            d_ct,
            cuda_sks,
            scalar_for_multiplication,
            cuda_sks,
            noise_simulation_modulus_switch_config,
            drift_key,
            &d_accumulator,
            br_input_modulus_log,
            &side_resources,
        );

    //let before_ms = after_drift.as_ref().unwrap_or(&after_ks);
    let input_list = input_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let input_ct = LweCiphertext::from_container(
        input_list.clone().into_container(),
        input_list.ciphertext_modulus(),
    );
    let input = DynLwe::U64(input_ct);

    let after_br_list = after_br_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let after_br_ct = LweCiphertext::from_container(
        after_br_list.clone().into_container(),
        after_br_list.ciphertext_modulus(),
    );
    let after_br = DynLwe::U64(after_br_ct);

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

    let before_ms_gpu: &CudaDynLwe = after_drift_gpu.as_ref().unwrap_or(&after_ks_gpu);
    let before_ms_list = before_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let before_ms_ct = LweCiphertext::from_container(
        before_ms_list.clone().into_container(),
        before_ms_list.ciphertext_modulus(),
    );
    let before_ms = DynLwe::U64(before_ms_ct);

    let after_ms_list = after_ms_gpu.as_lwe_64().to_lwe_ciphertext_list(streams);
    let after_ms_ct = LweCiphertext::from_container(
        after_ms_list.clone().into_container(),
        after_ms_list.ciphertext_modulus(),
    );
    let after_ms = DynLwe::U64(after_ms_ct);

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new_from_lwe(
                &input.as_lwe_64(),
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new_from_lwe(
                &after_br.as_lwe_64(),
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

fn encrypt_br_dp_ks_any_ms_noise_helper_gpu(
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
    NoiseSample,
) {
    let (input, after_br, after_dp, after_ks, before_ms, after_ms) =
        encrypt_br_dp_ks_any_ms_inner_helper_gpu(
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
    single_sks: &ServerKey,
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
            single_sks,
            single_cuda_sks,
            msg,
            scalar_for_multiplication,
            br_input_modulus_log,
            streams,
        );

    after_ms
}

fn noise_check_encrypt_br_dp_ks_ms_noise<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk =
        NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);
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

            match &standard_atomic_pattern_server_key.bootstrapping_key {
                ShortintBootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key: _,
                } => {
                    assert!(noise_simulation_bsk.matches_actual_bsk_gpu(&cuda_sks.bootstrapping_key))
                }
                ShortintBootstrappingKey::MultiBit { .. } => todo!(),
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
            noise_simulation_modulus_switch_config,
            noise_simulation_drift_key.as_ref(),
            &noise_simulation_accumulator,
            br_input_modulus_log,
            &(),
        )
    };

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let sample_input = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_new_noiseless_lwe(
                    &standard_atomic_pattern_client_key.lwe_secret_key,
                    CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap(),
                    0,
                    &sks.key.encoding(PaddingBit::Yes),
                    &mut engine.encryption_generator,
                )
            })
        }
        AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => {
            todo!("Manage generation of DynLwe as an additional impl on the ClientKey")
        }
    };

    let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&sample_input, &streams);
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
    let mut side_resources = CudaSideResources::new(&streams, block_info);

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) = br_dp_ks_any_ms(
            gpu_sample_input,
            &cuda_sks,
            max_scalar_mul,
            &cuda_sks,
            noise_simulation_modulus_switch_config,
            drift_key,
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

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .into_iter()
            .map(|_| {
                let (_input, _after_br, _after_dp, _after_ks, before_ms, after_ms) =
                    encrypt_br_dp_ks_any_ms_noise_helper_gpu(
                        params,
                        &cks.key,
                        &sks,
                        &cuda_sks,
                        0,
                        max_scalar_mul,
                        br_input_modulus_log,
                        &streams,
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

create_gpu_parameterized_test!(noise_check_encrypt_br_dp_ks_ms_noise {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn noise_check_encrypt_br_dp_ks_ms_pfail_gpu<P>(params: P)
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

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_iter()
        .map(|_| {
            let after_ms_decryption_result = encrypt_br_dp_ks_any_ms_pfail_helper_gpu(
                params,
                &cks.key,
                &sks,
                &cuda_sks,
                0,
                max_scalar_mul,
                br_input_modulus_log,
                &streams,
            );
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_gpu_parameterized_test!(noise_check_encrypt_br_dp_ks_ms_pfail_gpu {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
