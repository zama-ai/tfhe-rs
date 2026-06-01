use super::dp_ks_ms::any_ms;
use super::utils::noise_simulation::{
    DynLwe, DynLweSecretKeyView, NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey,
    NoiseSimulationModulusSwitchConfig,
};
use super::utils::to_json::{TestJsonGuard, TestResult};
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, noise_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::commons::math::random::XofSeed;
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DynamicDistribution, LweCiphertextCount, PlaintextCount,
};
use crate::core_crypto::commons::traits::{
    Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut,
    UnsignedInteger,
};
use crate::core_crypto::entities::{
    Cleartext, LweCiphertextOwned, LweCompactCiphertextList, LweCompactPublicKey, PlaintextList,
};
use crate::shortint::ciphertext::ReRandomizationSeed;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyView};
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, MetaParameters, ShortintCompactCiphertextListCastingMode,
    ShortintKeySwitchingParameters,
};
use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::shortint::Ciphertext;
use crate::this_function_name;
use rayon::prelude::*;

// TODO: remove once GPU has updated the cpk_ks_ms tests
// We do not re-use the function in the rerand one since we want to get rid of it
#[cfg(feature = "gpu")]
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
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
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
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>
        + AllocateMultiBitModSwitchResult<Output = MsResult, SideResources = Resources>
        + MultiBitModSwitch<MsResult, SideResources = Resources>,
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
    let (drift_technique_result, ms_result) = any_ms(
        &ks_result,
        modulus_switch_configuration,
        br_input_modulus_log,
        side_resources,
    );

    (input, ks_result, drift_technique_result, ms_result)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn cpk_rerand_ks_any_ms<
    InputCt,
    InputZeroReRand,
    ReRandCt,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    KsKeyDs,
    DriftKey,
    Resources,
>(
    input: InputCt,
    input_zero_rerand: InputZeroReRand,
    ksk_ds: &KsKeyDs,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    (InputCt, InputZeroReRand),
    ReRandCt,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    InputCt: for<'a> LweUncorrelatedAdd<
        &'a InputZeroReRand,
        Output = ReRandCt,
        SideResources = Resources,
    >,
    KsKeyDs: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ReRandCt, KsResult, SideResources = Resources>,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
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
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    // ReRand uncorrelated add
    let rerand_ct = input.lwe_uncorrelated_add(&input_zero_rerand, side_resources);

    let mut ks_result = ksk_ds.allocate_lwe_keyswitch_result(side_resources);
    ksk_ds.lwe_keyswitch(&rerand_ct, &mut ks_result, side_resources);

    // MS
    let (drift_technique_result, ms_result) = any_ms(
        &ks_result,
        modulus_switch_configuration,
        br_input_modulus_log,
        side_resources,
    );

    (
        (input, input_zero_rerand),
        rerand_ct,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn cpk_rerand_ks_any_ms_inner_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> (
    (DecryptionAndNoiseResult, DecryptionAndNoiseResult),
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
            ksk_ds_params,
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

    // Fresh encryption of 0 under the same compact public key, used for the ReRand
    let ct_zero_rerand = {
        let compact_list =
            cpk.encrypt_iter_with_modulus(core::iter::once(0), cpk.parameters.message_modulus.0);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let ((input, input_zero_rerand), after_rerand, after_ks_ds, after_drift, after_ms) =
        cpk_rerand_ks_any_ms(
            ct,
            ct_zero_rerand,
            ksk_ds,
            modulus_switch_config,
            br_input_modulus_log,
            &mut (),
        );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks_ds);

    let cpk_lwe_secret_key_dyn = cpk_private_key.lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    (
        (
            DecryptionAndNoiseResult::new_from_dyn_lwe(&input, &cpk_lwe_secret_key_dyn, msg),
            DecryptionAndNoiseResult::new_from_dyn_lwe(
                &input_zero_rerand,
                &cpk_lwe_secret_key_dyn,
                0,
            ),
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_rerand, &cpk_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_ks_ds, &small_lwe_secret_key_dyn, msg),
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
fn cpk_rerand_ks_any_ms_noise_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> (
    (NoiseSample, NoiseSample),
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
) {
    let ((input, input_zero_rerand), after_rerand, after_ks_ds, before_ms, after_ms) =
        cpk_rerand_ks_any_ms_inner_helper(
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
        (
            input
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
            input_zero_rerand
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
        ),
        after_rerand
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
fn cpk_rerand_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    ksk_ds_params: ShortintKeySwitchingParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_ds: &KeySwitchingKeyView<'_>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
) -> DecryptionAndNoiseResult {
    let ((_input, _input_zero_rerand), _after_rerand, _after_ks_ds, _before_ms, after_ms) =
        cpk_rerand_ks_any_ms_inner_helper(
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

    after_ms
}

fn noise_check_encrypt_cpk_rerand_ks_any_ms_noise(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (params, cpk_params, ksk_ds_params) = {
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

    let ksk_ds_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_ds_builder.as_key_switching_key_view();

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_ds =
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(cpk_params, ksk_ds_params, params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_ksk_ds.matches_actual_shortint_keyswitching_key(&ksk_ds));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));

    let (
        (_input_sim, _input_zero_rerand_sim),
        _after_rerand_sim,
        _after_ks_ds_sim,
        _after_drift_sim,
        after_ms_sim,
    ) = {
        let noise_simulation_input = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
        let noise_simulation_input_zero_rerand = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
        cpk_rerand_ks_any_ms(
            noise_simulation_input,
            noise_simulation_input_zero_rerand,
            &noise_simulation_ksk_ds,
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
    let sample_input_zero_rerand = {
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
        let ((_input, _input_zero_rerand), _after_rerand, _after_ks_ds, _after_drift, after_ms) =
            cpk_rerand_ks_any_ms(
                sample_input,
                sample_input_zero_rerand,
                &ksk_ds,
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
                let (
                    (_input, _input_zero_rerand),
                    _after_rerand,
                    _after_ks_ds,
                    before_ms,
                    after_ms,
                ) = cpk_rerand_ks_any_ms_noise_helper(
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

create_parameterized_stringified_test!(noise_check_encrypt_cpk_rerand_ks_any_ms_noise {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_cpk_rerand_ks_any_ms_pfail(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (params, cpk_params, ksk_ds_params) = {
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

    let ksk_ds_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_ds_builder.as_key_switching_key_view();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result = cpk_rerand_ks_any_ms_pfail_helper(
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
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result, &guard);
}

create_parameterized_stringified_test!(noise_check_encrypt_cpk_rerand_ks_any_ms_pfail {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

pub(crate) fn encrypt_lwe_compact_ciphertext_list_with_compact_public_key_worst_case<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    worst_case_tuniform_value: Scalar,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    use crate::core_crypto::algorithms::slice_algorithms::{
        slice_semi_reverse_negacyclic_convolution, slice_wrapping_add_assign,
    };

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_compact_public_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_compact_public_key.lwe_dimension()
    );

    assert!(
        lwe_compact_public_key.ciphertext_modulus() == output.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.ciphertext_modulus(),
        lwe_compact_public_key.ciphertext_modulus()
    );

    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between LweCiphertextCount of output ciphertext and \
        PlaintextCount of input list. Got {:?} in output, and {:?} in input plaintext list.",
        output.lwe_ciphertext_count(),
        encoded.plaintext_count()
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();
    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();

    // The worst case for the binary_random_vector is all ones
    let binary_random_vector = vec![Scalar::ONE; output_mask_list.lwe_mask_list_size()];

    let mask_noise = vec![worst_case_tuniform_value; output_mask_list.lwe_mask_list_size()];
    let body_noise = vec![worst_case_tuniform_value; encoded.plaintext_count().0];

    let max_ciphertext_per_bin = lwe_compact_public_key.lwe_dimension().0;
    output_mask_list
        .iter_mut()
        .zip(
            output_body_list
                .chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.chunks(max_ciphertext_per_bin))
                .zip(mask_noise.as_slice().chunks(max_ciphertext_per_bin))
                .zip(body_noise.as_slice().chunks(max_ciphertext_per_bin)),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    (
                        ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                        mask_noise,
                    ),
                    body_noise,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we
                // create a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; max_ciphertext_per_bin];

                slice_semi_reverse_negacyclic_convolution(
                    output_mask.as_mut(),
                    pk_mask.as_ref(),
                    binary_random_slice,
                );

                // Fill the temp buffer with b convolved with r
                slice_semi_reverse_negacyclic_convolution(
                    pk_body_convolved.as_mut_slice(),
                    pk_body.as_ref(),
                    binary_random_slice,
                );

                slice_wrapping_add_assign(output_mask.as_mut(), mask_noise);

                // Fill the body chunk afterward manually as it most likely will be smaller than
                // the full convolution result. rev(b convolved r) + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(
                        pk_body_convolved
                            .iter()
                            .rev()
                            .zip(input_plaintext_chunk.iter()),
                    )
                    .zip(body_noise)
                    .for_each(|((dst, (&src, plaintext)), body_noise)| {
                        *dst.data = src.wrapping_add(*body_noise).wrapping_add(*plaintext.0);
                    });
            },
        );
}

// Verify that all ciphertexts encrypted in a worst case scenario decrypt properly at each step of
// the circuit
fn sanity_check_encrypt_cpk_rerand_ks_any_ms_worst_case(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (params, cpk_params, ksk_ds_params) = {
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

    let max_tuniform_value = match cpk_params.encryption_noise_distribution {
        DynamicDistribution::Gaussian(_) => {
            panic!("This test only supports TUniform noise distributions")
        }
        DynamicDistribution::TUniform(tuniform) => tuniform.max_value_inclusive() as u64,
    };

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_ds_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_ds_builder.as_key_switching_key_view();

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();

    let cpk_lwe_secret_key_dyn = cpk_private_key.lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    let DynLweSecretKeyView::U64 { key: _, encoding } = cpk_lwe_secret_key_dyn else {
        panic!("Only U64 supported for CPK encryption")
    };

    let msg = cpk.parameters().message_modulus.0 * cpk.parameters().carry_modulus.0 - 1;
    let encoded = encoding.encode(Cleartext(msg));

    // Worst case encryption done at the core level: all noise samples are at the maximum value of
    // the TUniform distribution and the binary vector used for encryption contains only 1s, with
    // as many ciphertexts as the compact public key can pack in a single bin.
    let worst_case_lwe_list = {
        let plaintext_list =
            PlaintextList::new(encoded.0, PlaintextCount(cpk.key.lwe_dimension().0));

        let mut compact_lwe_list = LweCompactCiphertextList::new(
            0u64,
            cpk.key.lwe_dimension().to_lwe_size(),
            LweCiphertextCount(plaintext_list.plaintext_count().0),
            cpk_params.ciphertext_modulus,
        );

        encrypt_lwe_compact_ciphertext_list_with_compact_public_key_worst_case(
            &cpk.key,
            &mut compact_lwe_list,
            &plaintext_list,
            max_tuniform_value,
        );

        // We can expand it since, rerandomizing before or after expansion is equivalent
        // see sanity_check_encrypt_cpk_rerand_ks_any_ms_pbs which rerands for the shortint path
        // first and checks both execution paths agree
        compact_lwe_list.expand_into_lwe_ciphertext_list()
    };

    let lwe_ciphertext_count = worst_case_lwe_list.lwe_ciphertext_count();

    // Fresh encryptions of 0 under the same compact public key, used for the ReRand
    let zero_rerands = {
        let compact_list = cpk.encrypt_slice_with_modulus(
            &vec![0u64; lwe_ciphertext_count.0],
            cpk.parameters.message_modulus.0,
        );
        let expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), lwe_ciphertext_count.0);

        expanded
    };

    let inputs: Vec<(DynLwe, DynLwe)> = worst_case_lwe_list
        .iter()
        .zip(zero_rerands)
        .map(|(worst_case_lwe, zero_rerand)| {
            (
                DynLwe::U64(LweCiphertextOwned::from_container(
                    worst_case_lwe.as_ref().to_vec(),
                    worst_case_lwe.ciphertext_modulus(),
                )),
                DynLwe::U64(zero_rerand.ct),
            )
        })
        .collect();

    let results: Vec<_> = inputs
        .into_par_iter()
        .map(|(input, input_zero_rerand)| {
            let ((input, input_zero_rerand), after_rerand, after_ks_ds, after_drift, after_ms) =
                cpk_rerand_ks_any_ms(
                    input,
                    input_zero_rerand,
                    &ksk_ds,
                    modulus_switch_config,
                    compute_br_input_modulus_log,
                    &mut (),
                );

            let before_ms = after_drift.as_ref().unwrap_or(&after_ks_ds);

            (
                (
                    input.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &input,
                        &cpk_lwe_secret_key_dyn,
                        msg,
                    ),
                ),
                (
                    input_zero_rerand.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &input_zero_rerand,
                        &cpk_lwe_secret_key_dyn,
                        0,
                    ),
                ),
                (
                    after_rerand.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &after_rerand,
                        &cpk_lwe_secret_key_dyn,
                        msg,
                    ),
                ),
                (
                    after_ks_ds.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &after_ks_ds,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                ),
                (
                    before_ms.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        before_ms,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                ),
                (
                    after_ms.clone(),
                    DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
                        &after_ms,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                ),
            )
        })
        .collect();

    let all_decryptions_are_correct = results.iter().all(
        |(input, input_zero_rerand, after_rerand, after_ks_ds, before_ms, after_ms)| {
            [
                input.1,
                input_zero_rerand.1,
                after_rerand.1,
                after_ks_ds.1,
                before_ms.1,
                after_ms.1,
            ]
            .into_iter()
            .all(|decryption_result| {
                decryption_result
                    .get_noise_if_decryption_was_correct()
                    .is_some()
            })
        },
    );

    guard
        .write_results(all_decryptions_are_correct, None, TestResult::Empty {})
        .unwrap();

    let mut all_ok = true;

    // We check each step to preserve failure details and print the invalid case if one occurs
    for (idx, (input, input_zero_rerand, after_rerand, after_ks_ds, before_ms, after_ms)) in
        results.into_iter().enumerate()
    {
        let (input_ct, noise_input_ok) = (
            input.0,
            input.1.get_noise_if_decryption_was_correct().is_some(),
        );
        let (input_zero_rerand_ct, noise_input_zero_rerand_ok) = (
            input_zero_rerand.0,
            input_zero_rerand
                .1
                .get_noise_if_decryption_was_correct()
                .is_some(),
        );
        let (after_rerand_ct, noise_after_rerand_ok) = (
            after_rerand.0,
            after_rerand
                .1
                .get_noise_if_decryption_was_correct()
                .is_some(),
        );
        let (after_ks_ds_ct, noise_after_ks_ds_ok) = (
            after_ks_ds.0,
            after_ks_ds
                .1
                .get_noise_if_decryption_was_correct()
                .is_some(),
        );
        let (before_ms_ct, noise_before_ms_ok) = (
            before_ms.0,
            before_ms.1.get_noise_if_decryption_was_correct().is_some(),
        );
        let (after_ms_ct, noise_after_ms_ok) = (
            after_ms.0,
            after_ms.1.get_noise_if_decryption_was_correct().is_some(),
        );
        let current_ok = noise_input_ok
            && noise_input_zero_rerand_ok
            && noise_after_rerand_ok
            && noise_after_ks_ds_ok
            && noise_before_ms_ok
            && noise_after_ms_ok;

        all_ok = all_ok && current_ok;

        if !current_ok {
            println!(
                "Problem for ciphertext at index {idx}:\n\
                input_ct: {input_ct:?} \n\
                input_zero_rerand_ct: {input_zero_rerand_ct:?} \n\
                after_rerand_ct: {after_rerand_ct:?} \n\
                after_ks_ds_ct: {after_ks_ds_ct:?} \n\
                before_ms_ct: {before_ms_ct:?} \n\
                after_ms_ct: {after_ms_ct:?}"
            )
        }
    }

    assert!(
        all_ok,
        "Test fail, current secret keys : cpk_lwe_secret_key_dyn={cpk_lwe_secret_key_dyn:?}, \
        small_lwe_secret_key_dyn={small_lwe_secret_key_dyn:?}"
    )
}

create_parameterized_stringified_test!(sanity_check_encrypt_cpk_rerand_ks_any_ms_worst_case {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

// Verify that the cpk_rerand_ks_any_ms circuit followed by a PBS corresponds exactly to what
// happens in the shortint API calls, i.e. ReRand on the compact list followed by an expand with
// casting
fn sanity_check_encrypt_cpk_rerand_ks_any_ms_pbs(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (params, cpk_params, ksk_ds_params, orig_cast_mode) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let (cpk_params, orig_cast_mode) = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            let orig_cast_mode = cpk_params.expansion_kind;
            cpk_params.expansion_kind =
                CompactCiphertextListExpansionKind::NoCasting(compute_params.atomic_pattern());
            (cpk_params, orig_cast_mode)
        };

        assert!(matches!(
            orig_cast_mode,
            CompactCiphertextListExpansionKind::RequiresCasting
        ));

        (
            compute_params,
            cpk_params,
            dedicated_cpk_params.ksk_params,
            orig_cast_mode,
        )
    };

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let ksk_ds_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), ksk_ds_params);
    let ksk_ds: KeySwitchingKeyView<'_> = ksk_ds_builder.as_key_switching_key_view();

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();

    let id_lut = sks.generate_lookup_table(|x| x);

    // As many ciphertexts as the compact public key can pack in a single bin, i.e. the maximum
    // capacity of the compact list before a second bin is required
    let cpk_max_ct_capacity = cpk.key.lwe_dimension().0;

    let msgs = vec![0u64; cpk_max_ct_capacity];

    let mut results: Vec<(DynLwe, Ciphertext)> = Vec::new();

    for idx in 0..10 {
        let seed_bytes = vec![idx as u8; 256 / 8];
        let rerand_xof_seed = XofSeed::new(seed_bytes, *b"TFHE_Enc");

        // Manually build as the seed is made non Clone to protect user normally
        let manual_circuit_rerand_seed = ReRandomizationSeed(rerand_xof_seed.clone());
        let shortint_rerand_seed = ReRandomizationSeed(rerand_xof_seed);

        let (ap_inputs_expanded, shortint_results) = {
            let no_casting_compact_list =
                cpk.encrypt_slice_with_modulus(&msgs, cpk.parameters.message_modulus.0);

            let mut shortint_casting_compact_list = no_casting_compact_list.clone();
            shortint_casting_compact_list.expansion_kind = orig_cast_mode;

            let ap_inputs_expanded = no_casting_compact_list
                .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
                .unwrap();
            assert_eq!(ap_inputs_expanded.len(), cpk_max_ct_capacity);

            // Shortint ReRand adds an encryption of zero on the compact list before the expansion,
            // it is equivalent to adding the expanded encryption of zero on the expanded input as
            // the expansion process is linear
            cpk.re_randomize_compact_ciphertext_lists(
                core::iter::once(&mut shortint_casting_compact_list),
                shortint_rerand_seed,
            )
            .unwrap();

            // Shortint expand will do the KS + MS + PBS all on its own
            let shortint_results = shortint_casting_compact_list
                .expand(ShortintCompactCiphertextListCastingMode::CastIfNecessary {
                    casting_key: ksk_ds,
                    functions: None, // Will fallback to ID LUT which is what we want
                })
                .unwrap();
            assert_eq!(shortint_results.len(), cpk_max_ct_capacity);

            (ap_inputs_expanded, shortint_results)
        };

        // Same encryptions of zero as the ones added by the shortint ReRand as the seeds match
        let input_zero_rerands = cpk
            .prepare_cpk_zero_for_rerand(
                manual_circuit_rerand_seed,
                LweCiphertextCount(cpk_max_ct_capacity),
            )
            .expand_into_lwe_ciphertext_list();

        let per_ct_inputs: Vec<(DynLwe, DynLwe, Ciphertext)> = ap_inputs_expanded
            .into_iter()
            .zip(input_zero_rerands.iter())
            .zip(shortint_results)
            .map(|((ap_input, input_zero_rerand), shortint_res)| {
                (
                    DynLwe::U64(ap_input.ct),
                    DynLwe::U64(LweCiphertextOwned::from_container(
                        input_zero_rerand.as_ref().to_vec(),
                        input_zero_rerand.ciphertext_modulus(),
                    )),
                    shortint_res,
                )
            })
            .collect();

        results.par_extend(per_ct_inputs.into_par_iter().map(
            |(sample_input, input_zero_rerand, shortint_res)| {
                let (
                    (_input, _input_zero_rerand),
                    _after_rerand,
                    _after_ks_ds,
                    _after_drift,
                    after_ms,
                ) = cpk_rerand_ks_any_ms(
                    sample_input,
                    input_zero_rerand,
                    &ksk_ds,
                    modulus_switch_config,
                    compute_br_input_modulus_log,
                    &mut (),
                );

                // Complete the AP by computing the PBS to match shortint
                let mut pbs_result = id_lut.allocate_lwe_bootstrap_result(&mut ());
                sks.apply_generic_blind_rotation(&after_ms, &mut pbs_result, &id_lut);

                (pbs_result, shortint_res)
            },
        ));
    }

    let all_result_match = results
        .iter()
        .all(|(lhs, rhs)| lhs.as_lwe_64() == rhs.ct.as_view());

    guard
        .write_results(all_result_match, None, TestResult::Empty {})
        .unwrap();

    // We check each step to preserve failure details and print the invalid case if one occurs
    for (pbs_result, shortint_res) in results.iter() {
        assert_eq!(pbs_result.as_lwe_64(), shortint_res.ct.as_view());
    }
}

create_parameterized_stringified_test!(sanity_check_encrypt_cpk_rerand_ks_any_ms_pbs {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
