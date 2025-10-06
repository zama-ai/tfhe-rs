use super::utils::noise_simulation::{
    DynLwe, NoiseSimulationDriftTechniqueKey, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweFourierBsk, NoiseSimulationLweKeyswitchKey,
    NoiseSimulationModulusSwitchConfig,
};
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyView};
use crate::shortint::list_compression::{CompressionPrivateKeys, DecompressionKey};
use crate::shortint::parameters::test_params::{
    TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, CompressionParameters,
    ShortintCompactCiphertextListCastingMode, ShortintKeySwitchingParameters,
};
use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulus;
use crate::shortint::server_key::ServerKey;
use crate::shortint::PaddingBit;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn cpk_ks_any_ms<
    InputCt,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    KsKeyDs,
    DriftKey,
    Resources,
>(
    input: InputCt,
    ksk_ds: &KsKeyDs,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig,
    mod_switch_noise_reduction_key: Option<&DriftKey>,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (InputCt, KsResult, Option<DriftTechniqueResult>, MsResult)
where
    KsKeyDs: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<InputCt, KsResult, SideResources = Resources>,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>,
    DriftKey: AllocateDriftTechniqueStandardModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DriftTechniqueStandardModSwitch<
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    let mut ks_result = ksk_ds.allocate_lwe_keyswitch_result(side_resources);
    ksk_ds.lwe_keyswitch(&input, &mut ks_result, side_resources);

    // MS
    let (drift_technique_result, ms_result) =
        match (modulus_switch_configuration, mod_switch_noise_reduction_key) {
            (
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction,
                Some(mod_switch_noise_reduction_key),
            ) => {
                let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key
                    .allocate_drift_technique_standard_mod_switch_result(side_resources);
                mod_switch_noise_reduction_key.drift_technique_and_standard_mod_switch(
                    br_input_modulus_log,
                    &ks_result,
                    &mut drift_technique_result,
                    &mut ms_result,
                    side_resources,
                );

                (Some(drift_technique_result), ms_result)
            }
            (NoiseSimulationModulusSwitchConfig::Standard, None) => {
                let mut ms_result = ks_result.allocate_standard_mod_switch_result(side_resources);
                ks_result.standard_mod_switch(br_input_modulus_log, &mut ms_result, side_resources);

                (None, ms_result)
            }
            (NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction, None) => {
                let mut ms_result = ks_result
                    .allocate_centered_binary_shifted_standard_mod_switch_result(side_resources);
                ks_result.centered_binary_shifted_and_standard_mod_switch(
                    br_input_modulus_log,
                    &mut ms_result,
                    side_resources,
                );

                (None, ms_result)
            }
            _ => panic!("Inconsistent modulus switch and drift key configuration"),
        };

    (input, ks_result, drift_technique_result, ms_result)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_inner_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let mut engine = ShortintEngine::new();
    let thread_cpk_private_key;
    let thread_cpk;
    let thread_ksk_ds_builder;
    let thread_ksk_ds;
    let thread_cks;
    let thread_sks;
    let (cpk_private_key, cpk, ksk_ds, cks, sks) = if should_use_single_key_debug() {
        (
            single_cpk_private_key,
            single_cpk,
            single_ksk_ds,
            single_cks,
            single_sks,
        )
    } else {
        thread_cpk_private_key = CompactPrivateKey::new_with_engine(cpk_params, &mut engine);
        thread_cpk = CompactPublicKey::new_with_engine(&thread_cpk_private_key, &mut engine);
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        thread_ksk_ds_builder = KeySwitchingKeyBuildHelper::new_with_engine(
            (&thread_cpk_private_key, None),
            (&thread_cks, &thread_sks),
            rerand_ksk_params,
            &mut engine,
        );
        thread_ksk_ds = thread_ksk_ds_builder.as_key_switching_key_view();

        (
            &thread_cpk_private_key,
            &thread_cpk,
            &thread_ksk_ds,
            &thread_cks,
            &thread_sks,
        )
    };

    let br_input_modulus_log = sks.br_input_modulus_log();
    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let ct = {
        let compact_list = cpk.encrypt_iter_with_modulus_with_engine(
            core::iter::once(msg),
            cpk.parameters.message_modulus.0,
            &mut engine,
        );
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let (input, after_ks_ds, after_drift, after_ms) = cpk_ks_any_ms(
        ct,
        ksk_ds,
        noise_simulation_modulus_switch_config,
        drift_key,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks_ds);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            let params = standard_atomic_pattern_client_key.parameters;
            let encoding = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };

            let cpk_lwe_secret_key = cpk_private_key.key();

            let small_compute_lwe_secret_key =
                standard_atomic_pattern_client_key.small_lwe_secret_key();
            (
                DecryptionAndNoiseResult::new_from_lwe(
                    &input.as_lwe_64(),
                    &cpk_lwe_secret_key,
                    msg,
                    &encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ks_ds.as_lwe_64(),
                    &small_compute_lwe_secret_key,
                    msg,
                    &encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &before_ms.as_lwe_64(),
                    &small_compute_lwe_secret_key,
                    msg,
                    &encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ms.as_lwe_64(),
                    &small_compute_lwe_secret_key,
                    msg,
                    &encoding,
                ),
            )
        }
        AtomicPatternClientKey::KeySwitch32(ks32_atomic_pattern_client_key) => {
            let params = ks32_atomic_pattern_client_key.parameters;
            let compute_encoding_u32 = ShortintEncoding {
                ciphertext_modulus: params.post_keyswitch_ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };
            let compute_encoding_u64 = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };

            let cpk_lwe_secret_key = cpk_private_key.key();

            let small_compute_lwe_secret_key =
                ks32_atomic_pattern_client_key.small_lwe_secret_key();

            let msg_u32: u32 = msg.try_into().unwrap();

            (
                DecryptionAndNoiseResult::new_from_lwe(
                    &input.as_lwe_64(),
                    &cpk_lwe_secret_key,
                    msg,
                    &compute_encoding_u64,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ks_ds.as_lwe_32(),
                    &small_compute_lwe_secret_key,
                    msg_u32,
                    &compute_encoding_u32,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &before_ms.as_lwe_32(),
                    &small_compute_lwe_secret_key,
                    msg_u32,
                    &compute_encoding_u32,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ms.as_lwe_32(),
                    &small_compute_lwe_secret_key,
                    msg_u32,
                    &compute_encoding_u32,
                ),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_noise_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> (NoiseSample, NoiseSample, NoiseSample, NoiseSample) {
    let (input, after_ks_ds, before_ms, after_ms) = encrypt_br_rerand_dp_ks_any_ms_inner_helper(
        params,
        cpk_params,
        ksk_ds_params,
        single_cpk_private_key,
        single_cpk,
        single_ksk_ds,
        single_cks,
        single_sks,
        msg,
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
fn encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_ks_ds, _before_ms, after_ms) = encrypt_br_rerand_dp_ks_any_ms_inner_helper(
        params,
        cpk_params,
        rerand_ksk_params,
        single_cpk_private_key,
        single_cpk,
        single_ksk_ds,
        single_cks,
        single_sks,
        msg,
    );

    after_ms
}

fn noise_check_encrypt_cpk_ks_ms_noise<P>(
    params: P,
    mut cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
) where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();

    // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after expand
    let cpk_params = {
        cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
            params.encryption_key_choice().into_pbs_order(),
        );
        cpk_params
    };

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_ds_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_ds_builder.as_key_switching_key_view();

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_ds =
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(cpk_params, ksk_ds_params, params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);

    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        noise_simulation_modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_ksk_ds.matches_actual_shortint_keyswitching_key(&ksk_ds));
    match (noise_simulation_drift_key, drift_key) {
        (Some(noise_simulation_drift_key), Some(drift_key)) => {
            assert!(noise_simulation_drift_key.matches_actual_shortint_server_key(drift_key))
        }
        (None, None) => (),
        _ => panic!("Inconsistent Drift Key configuration"),
    }

    let max_scalar_mul = sks.max_noise_level.get();

    let (_input_sim, _after_ks_ds_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation_input = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
        cpk_ks_any_ms(
            noise_simulation_input,
            &noise_simulation_ksk_ds,
            noise_simulation_modulus_switch_config,
            noise_simulation_drift_key.as_ref(),
            compute_br_input_modulus_log,
            &mut (),
        )
    };

    let sample_input = {
        let compact_list = cpk.encrypt_slice(&[0]);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_ks_ds, _before_ms, after_ms) = cpk_ks_any_ms(
            sample_input,
            &ksk_ds,
            noise_simulation_modulus_switch_config,
            drift_key,
            compute_br_input_modulus_log,
            &mut (),
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
            .into_par_iter()
            .map(|_| {
                let (_input, _after_ks_ds, before_ms, after_ms) =
                    encrypt_br_rerand_dp_ks_any_ms_noise_helper(
                        params,
                        cpk_params,
                        ksk_ds_params,
                        &cpk_private_key,
                        &cpk,
                        &ksk_ds,
                        &cks,
                        &sks,
                        0,
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

// create_parameterized_test!(noise_check_encrypt_br_dp_ks_ms_noise {
//     TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
//     TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
//     TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
// });

#[test]
fn test_noise_check_encrypt_cpk_ks_ms_noise_test_param_message_2_carry_2_ks_pbs_tuniform_2m128() {
    noise_check_encrypt_cpk_ks_ms_noise(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_encrypt_cpk_ks_ms_noise_test_param_message_2_carry_2_ks32_tuniform_2m128() {
    noise_check_encrypt_cpk_ks_ms_noise(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_encrypt_cpk_ks_ms_pfail<P>(
    params: P,
    mut cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
) where
    P: Into<AtomicPatternParameters> + Copy,
{
    // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
    // expand
    let cpk_params = {
        let params: AtomicPatternParameters = params.into();

        cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
            params.encryption_key_choice().into_pbs_order(),
        );
        cpk_params
    };

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

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_rerand_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_rerand_builder.as_key_switching_key_view();

    let max_scalar_mul = sks.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result = encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
                params,
                cpk_params,
                rerand_ksk_params,
                &cpk_private_key,
                &cpk,
                &ksk_ds,
                &cks,
                &sks,
                0,
            );
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

#[test]
fn test_pfail_check_encrypt_cpk_ks_ms_noise_test_param_message_2_carry_2_ks_pbs_tuniform_2m128() {
    noise_check_encrypt_cpk_ks_ms_pfail(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_pfail_check_encrypt_cpk_ks_ms_noise_test_param_message_2_carry_2_ks32_tuniform_2m128() {
    noise_check_encrypt_cpk_ks_ms_pfail(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
