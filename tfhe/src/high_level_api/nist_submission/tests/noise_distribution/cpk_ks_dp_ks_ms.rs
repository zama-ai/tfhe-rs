use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::nist_submission::NIST_META_PARAMS_2_2;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyView};
use crate::shortint::parameters::{
    CarryModulus, CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    MetaParameters, ShortintCompactCiphertextListCastingMode, ShortintKeySwitchingParameters,
};
use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::shortint::server_key::tests::noise_distribution::dp_ks_ms::dp_ks_any_ms;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::TestJsonGuard;
use crate::shortint::server_key::tests::noise_distribution::utils::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult,
    AllocateDriftTechniqueStandardModSwitchResult, AllocateLweKeyswitchResult,
    AllocateMultiBitModSwitchResult, AllocateStandardModSwitchResult,
    CenteredBinaryShiftedStandardModSwitch, DriftTechniqueStandardModSwitch, LweKeyswitch,
    MultiBitModSwitch, ScalarMul, StandardModSwitch,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, noise_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::shortint::AtomicPatternParameters;
use crate::this_function_name;
use rayon::prelude::*;
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn cpk_ks_dp_ks_any_ms<
    InputCt,
    AfterCastKsResult,
    ScalarMulResult,
    AfterComputeKsResult,
    DriftTechniqueResult,
    MsResult,
    DPScalar,
    KsKeyDs,
    KsKeyCompute,
    DriftKey,
    Resources,
>(
    input: InputCt,
    ksk_ds: &KsKeyDs,
    scalar: DPScalar,
    ksk_compute: &KsKeyCompute,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    AfterCastKsResult,
    ScalarMulResult,
    AfterComputeKsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    KsKeyDs: AllocateLweKeyswitchResult<Output = AfterCastKsResult, SideResources = Resources>
        + LweKeyswitch<InputCt, AfterCastKsResult, SideResources = Resources>,
    AfterCastKsResult: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    KsKeyCompute: AllocateLweKeyswitchResult<Output = AfterComputeKsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, AfterComputeKsResult, SideResources = Resources>,
    AfterComputeKsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>
        + AllocateMultiBitModSwitchResult<Output = MsResult, SideResources = Resources>
        + MultiBitModSwitch<MsResult, SideResources = Resources>,
    DriftKey: AllocateDriftTechniqueStandardModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DriftTechniqueStandardModSwitch<
            AfterComputeKsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    let mut after_cast_ks = ksk_ds.allocate_lwe_keyswitch_result(side_resources);
    ksk_ds.lwe_keyswitch(&input, &mut after_cast_ks, side_resources);

    let (after_cast_ks, after_dp, after_compute_ks, drift_technique_result, ms_result) =
        dp_ks_any_ms(
            after_cast_ks,
            scalar,
            ksk_compute,
            modulus_switch_configuration,
            br_input_modulus_log,
            side_resources,
        );

    (
        input,
        after_cast_ks,
        after_dp,
        after_compute_ks,
        drift_technique_result,
        ms_result,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_dp_ks_any_ms_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_from_cpk_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_from_cpk: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let mut engine = ShortintEngine::new();
    let thread_cpk_private_key;
    let thread_cpk;
    let thread_ksk_from_cpk_builder;
    let thread_ksk_from_cpk;
    let thread_cks;
    let thread_sks;
    let (cpk_private_key, cpk, ksk_from_cpk, cks, sks) = if should_use_single_key_debug() {
        (
            single_cpk_private_key,
            single_cpk,
            single_ksk_from_cpk,
            single_cks,
            single_sks,
        )
    } else {
        thread_cpk_private_key = CompactPrivateKey::new_with_engine(cpk_params, &mut engine);
        thread_cpk = CompactPublicKey::new_with_engine(&thread_cpk_private_key, &mut engine);
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        thread_ksk_from_cpk_builder = KeySwitchingKeyBuildHelper::new_with_engine(
            (&thread_cpk_private_key, None),
            (&thread_cks, &thread_sks),
            ksk_from_cpk_params,
            &mut engine,
        );
        thread_ksk_from_cpk = thread_ksk_from_cpk_builder.as_key_switching_key_view();

        (
            &thread_cpk_private_key,
            &thread_cpk,
            &thread_ksk_from_cpk,
            &thread_cks,
            &thread_sks,
        )
    };

    let br_input_modulus_log = sks.br_input_modulus_log();
    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();

    let ct = {
        let compact_list =
            cpk.encrypt_iter_with_modulus(core::iter::once(msg), cpk.parameters.message_modulus.0);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let (input, after_cpk_ks, after_dp, after_compute_ks, after_drift, after_ms) =
        cpk_ks_dp_ks_any_ms(
            ct,
            ksk_from_cpk,
            scalar_for_multiplication,
            sks,
            modulus_switch_config,
            br_input_modulus_log,
            &mut (),
        );

    let before_ms = after_drift.as_ref().unwrap_or(&after_compute_ks);

    let cpk_lwe_secret_key_dyn = cpk_private_key.lwe_secret_key_as_dyn();
    let large_lwe_secret_key_dyn = cks.large_lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    (
        DecryptionAndNoiseResult::new_from_dyn_lwe(&input, &cpk_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_cpk_ks, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_dp, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &after_compute_ks,
            &small_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(before_ms, &small_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
            &after_ms,
            &small_lwe_secret_key_dyn,
            msg,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_from_cpk_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_from_cpk: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_cpk_ks, _after_dp, _after_compute_ks, _before_ms, after_ms) =
        cpk_ks_dp_ks_any_ms_helper(
            params,
            cpk_params,
            ksk_from_cpk_params,
            single_cpk_private_key,
            single_cpk,
            single_ksk_from_cpk,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
        );

    after_ms
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_ks_dp_ks_any_ms_noise_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_from_cpk_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_from_cpk: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (NoiseSample, NoiseSample) {
    let (_input, _after_cpk_ks, _after_dp, _after_compute_ks, before_ms, after_ms) =
        cpk_ks_dp_ks_any_ms_helper(
            params,
            cpk_params,
            ksk_from_cpk_params,
            single_cpk_private_key,
            single_cpk,
            single_ksk_from_cpk,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
        );

    (
        before_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
    )
}

fn noise_check_encrypt_cpk_ks_dp_ks_ms_noise(meta_params: MetaParameters, filename_suffix: &str) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (params, cpk_params, ksk_from_cpk_params) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind =
                CompactCiphertextListExpansionKind::NoCasting(compute_params.atomic_pattern());
            cpk_params
        };

        (compute_params, cpk_params, dedicated_cpk_params.ksk_params)
    };

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_from_cpk_builder = KeySwitchingKeyBuildHelper::new(
        (&cpk_private_key, None),
        (&cks, &sks),
        ksk_from_cpk_params,
    );
    let ksk_from_cpk: KeySwitchingKeyView<'_> = ksk_from_cpk_builder.as_key_switching_key_view();

    let noise_simulation_compute_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_from_cpk = NoiseSimulationLweKeyswitchKey::new_from_cpk_params(
        cpk_params,
        ksk_from_cpk_params,
        params,
    );
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_compute_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_ksk_from_cpk.matches_actual_shortint_keyswitching_key(&ksk_from_cpk));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));

    let max_scalar_mul = sks.max_noise_level.get();
    let (
        _input_sim,
        _after_cpk_ks_sim,
        _after_dp_sim,
        _after_compute_ks_sim,
        _after_drift_sim,
        after_ms_sim,
    ) = {
        let noise_simulation_input = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
        cpk_ks_dp_ks_any_ms(
            noise_simulation_input,
            &noise_simulation_ksk_from_cpk,
            max_scalar_mul,
            &noise_simulation_compute_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
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
        let (_input, _after_cpk_ks, _after_dp, _after_compute_ks, _after_drift, after_ms) =
            cpk_ks_dp_ks_any_ms(
                sample_input,
                &ksk_from_cpk,
                max_scalar_mul,
                &sks,
                modulus_switch_config,
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
                let (before_ms, after_ms) = cpk_ks_dp_ks_any_ms_noise_helper(
                    params,
                    cpk_params,
                    ksk_from_cpk_params,
                    &cpk_private_key,
                    &cpk,
                    &ksk_from_cpk,
                    &cks,
                    &sks,
                    0,
                    max_scalar_mul,
                );
                (before_ms.value, after_ms.value)
            })
            .unzip();

        noise_samples_before_ms.extend(current_noise_sample_before_ms);
        noise_samples_after_ms.extend(current_noise_samples_after_ms);
    }

    let before_ms_normality = normality_check(&noise_samples_before_ms, "before ms", 0.01);

    let mean_variance_result = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        expected_average_after_ms,
        after_ms_sim.variance(),
        params.lwe_noise_distribution(),
        after_ms_sim.lwe_dimension(),
        after_ms_sim.modulus().as_f64(),
    );

    noise_check(
        &guard,
        mean_variance_result,
        Some(before_ms_normality.null_hypothesis_is_valid),
    );
}

create_parameterized_stringified_test!(noise_check_encrypt_cpk_ks_dp_ks_ms_noise {
    NIST_META_PARAMS_2_2,
});

fn noise_check_encrypt_cpk_ks_dp_ks_ms_pfail(meta_params: MetaParameters, filename_suffix: &str) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();

    let (params, cpk_params, ksk_from_cpk_params) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind =
                CompactCiphertextListExpansionKind::NoCasting(compute_params.atomic_pattern());
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

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_from_cpk_builder = KeySwitchingKeyBuildHelper::new(
        (&cpk_private_key, None),
        (&cks, &sks),
        ksk_from_cpk_params,
    );
    let ksk_from_cpk: KeySwitchingKeyView<'_> = ksk_from_cpk_builder.as_key_switching_key_view();

    let max_scalar_mul = sks.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            cpk_ks_dp_ks_any_ms_pfail_helper(
                params,
                cpk_params,
                ksk_from_cpk_params,
                &cpk_private_key,
                &cpk,
                &ksk_from_cpk,
                &cks,
                &sks,
                0,
                max_scalar_mul,
            )
            .failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result, &guard);
}

create_parameterized_stringified_test!(noise_check_encrypt_cpk_ks_dp_ks_ms_pfail {
    NIST_META_PARAMS_2_2,
});
