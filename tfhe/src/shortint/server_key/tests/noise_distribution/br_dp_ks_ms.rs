use super::dp_ks_ms::dp_ks_any_ms;
use super::utils::noise_simulation::{
    NoiseSimulationDriftTechniqueKey, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweFourierBsk, NoiseSimulationLweKeyswitchKey,
    NoiseSimulationModulusSwitchConfig,
};
use super::utils::traits::*;
use super::utils::{
    encrypt_new_noiseless_lwe, mean_and_variance_check, normality_check, pfail_check,
    update_ap_params_for_pfail, DecryptionAndNoiseResult, NoiseSample, PfailTestMeta,
    PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::{CiphertextModulus, CiphertextModulusLog};
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternServerKey};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, CarryModulus};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulus;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::{ServerKey, ShortintBootstrappingKey};
use crate::shortint::{Ciphertext, PaddingBit};
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
pub fn br_dp_ks_any_ms<
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PBSKey,
    DPScalar,
    KsKey,
    DriftKey,
    Accumulator,
    Resources,
>(
    input: InputCt,
    bsk: &PBSKey,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig,
    mod_switch_noise_reduction_key: Option<&DriftKey>,
    accumulator: &Accumulator,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    // We need to be able to allocate the result and bootstrap the Input
    Accumulator: AllocateLweBootstrapResult<Output = PBSResult, SideResources = Resources>,
    PBSKey: LweClassicFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>,
    // Result of the PBS/Blind rotate needs to be multipliable by the scalar
    PBSResult: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>,
    // We need to be able to allocate the result and apply drift technique + mod switch it
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
    let mut pbs_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk.lwe_classic_fft_pbs(&input, &mut pbs_result, accumulator, side_resources);
    let (pbs_result, after_dp, ks_result, drift_technique_result, ms_result) = dp_ks_any_ms(
        pbs_result,
        scalar,
        ksk,
        modulus_switch_configuration,
        mod_switch_noise_reduction_key,
        br_input_modulus_log,
        side_resources,
    );

    (
        input,
        pbs_result,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}

#[allow(clippy::too_many_arguments)]
/// This function is used for sanity checks given we can't drop down to same level of details in the
/// shortint implementations.
pub fn br_dp_ks_any_ms_pbs<
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PBSKey,
    DPScalar,
    KsKey,
    DriftKey,
    Accumulator,
    Resources,
>(
    input: InputCt,
    bsk: &PBSKey,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig,
    mod_switch_noise_reduction_key: Option<&DriftKey>,
    accumulator: &Accumulator,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
    PBSResult,
)
where
    // We need to be able to allocate the result and bootstrap the Input and the mod switch output
    Accumulator: AllocateLweBootstrapResult<Output = PBSResult, SideResources = Resources>,
    PBSKey: LweClassicFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>
        + LweClassicFftBootstrap<MsResult, PBSResult, Accumulator, SideResources = Resources>,
    // Result of the PBS/Blind rotate needs to be multipliable by the scalar
    PBSResult: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>,
    // We need to be able to allocate the result and apply drift technique + mod switch it
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
    let (input, input_pbs_result, after_dp, ks_result, drift_technique_result, ms_result) =
        br_dp_ks_any_ms(
            input,
            bsk,
            scalar,
            ksk,
            modulus_switch_configuration,
            mod_switch_noise_reduction_key,
            accumulator,
            br_input_modulus_log,
            side_resources,
        );

    let mut output_pbs_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk.lwe_classic_fft_pbs(
        &ms_result,
        &mut output_pbs_result,
        accumulator,
        side_resources,
    );

    (
        input,
        input_pbs_result,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
        output_pbs_result,
    )
}

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint
fn sanity_check_encrypt_br_dp_ks_pbs<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let max_scalar_mul = sks.max_noise_level.get();

    let id_lut = sks.generate_lookup_table(|x| x);

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let small_lwe_sk = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            standard_atomic_pattern_client_key.lwe_secret_key.as_view()
        }
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    };

    let ms_ciphertext_modulus =
        CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
    let ms_encoding = ShortintEncoding {
        ciphertext_modulus: ms_ciphertext_modulus,
        message_modulus: sks.message_modulus,
        carry_modulus: sks.carry_modulus,
        padding_bit: PaddingBit::Yes,
    };

    for _ in 0..10 {
        let input_zero_as_lwe = ShortintEngine::with_thread_local_mut(|engine| {
            encrypt_new_noiseless_lwe(
                &small_lwe_sk,
                ms_ciphertext_modulus,
                0,
                &ms_encoding,
                &mut engine.encryption_generator,
            )
        });

        let (
            _input,
            input_pbs_result,
            _after_dp,
            _ks_result,
            _drift_technique_result,
            _ms_result,
            output_pbs_result,
        ) = br_dp_ks_any_ms_pbs(
            input_zero_as_lwe,
            &sks,
            max_scalar_mul,
            &sks,
            noise_simulation_modulus_switch_config,
            drift_key,
            &id_lut,
            br_input_modulus_log,
            &mut (),
        );

        // Shortint APIs are not granular enough to compare ciphertexts at the MS level
        // and inject arbitrary LWEs as input to the blind rotate step of the PBS.
        // So we start with the output of the input PBS from our test case and finish after
        // the second PBS and not the MS from our dedicated sanity function, which are
        // boundaries that are easily reached with shortint.
        // We don't want to use that dedicated function in statistical tests as it computes
        // 2 PBSes instead of one, the output of the seoncd PBS being of no interest for
        // noise measurement here.
        let mut shortint_res = Ciphertext::new(
            input_pbs_result.into_lwe_64(),
            id_lut.degree,
            NoiseLevel::NOMINAL,
            sks.message_modulus,
            sks.carry_modulus,
            sks.atomic_pattern.kind(),
        );

        sks.unchecked_scalar_mul_assign(&mut shortint_res, max_scalar_mul.try_into().unwrap());
        sks.apply_lookup_table_assign(&mut shortint_res, &id_lut);

        assert_eq!(
            output_pbs_result.into_lwe_64().as_view(),
            shortint_res.ct.as_view()
        );
    }
}

create_parameterized_test!(sanity_check_encrypt_br_dp_ks_pbs {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn encrypt_br_dp_ks_any_ms_inner_helper(
    params: AtomicPatternParameters,
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
    let thread_cks;
    let thread_sks;
    let (cks, sks) = if should_use_single_key_debug() {
        (single_cks, single_sks)
    } else {
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        (&thread_cks, &thread_sks)
    };

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let ct = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_new_noiseless_lwe(
                    &standard_atomic_pattern_client_key.lwe_secret_key,
                    CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap(),
                    0,
                    &sks.encoding(PaddingBit::Yes),
                    &mut engine.encryption_generator,
                )
            })
        }
        AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => todo!(),
    };

    let id_lut = sks.generate_lookup_table(|x| x);

    let (input, after_br, after_dp, after_ks, after_drift, after_ms) = br_dp_ks_any_ms(
        ct,
        sks,
        scalar_for_multiplication,
        sks,
        noise_simulation_modulus_switch_config,
        drift_key,
        &id_lut,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

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

fn encrypt_br_dp_ks_any_ms_noise_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
) {
    let (input, after_br, after_dp, after_ks, before_ms, after_ms) =
        encrypt_br_dp_ks_any_ms_inner_helper(
            params,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
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

fn encrypt_br_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) =
        encrypt_br_dp_ks_any_ms_inner_helper(
            params,
            single_cks,
            single_sks,
            msg,
            scalar_for_multiplication,
        );

    after_ms
}

fn noise_check_encrypt_br_dp_ks_ms_noise<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk =
        NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);

    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let expected_average_after_ms =
        noise_simulation_modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    let drift_key = match &sks.atomic_pattern {
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
                } => assert!(noise_simulation_bsk.matches_actual_bsk(bsk)),
                ShortintBootstrappingKey::MultiBit { .. } => todo!(),
            }

            match noise_simulation_modulus_switch_config {
                NoiseSimulationModulusSwitchConfig::Standard => None,
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&sks),
                NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
            }
        }
        _ => unimplemented!(),
    };

    let max_scalar_mul = sks.max_noise_level.get();

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
            &mut (),
        )
    };

    let id_lut = sks.generate_lookup_table(|x| x);
    let sample_input = match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            ShortintEngine::with_thread_local_mut(|engine| {
                encrypt_new_noiseless_lwe(
                    &standard_atomic_pattern_client_key.lwe_secret_key,
                    CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap(),
                    0,
                    &sks.encoding(PaddingBit::Yes),
                    &mut engine.encryption_generator,
                )
            })
        }
        AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => {
            todo!("Manage generation of DynLwe as an additional impl on the ClientKey")
        }
    };

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) = br_dp_ks_any_ms(
            sample_input,
            &sks,
            max_scalar_mul,
            &sks,
            noise_simulation_modulus_switch_config,
            drift_key,
            &id_lut,
            br_input_modulus_log,
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
                let (_input, _after_br, _after_dp, _after_ks, before_ms, after_ms) =
                    encrypt_br_dp_ks_any_ms_noise_helper(params, &cks, &sks, 0, max_scalar_mul);
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

create_parameterized_test!(noise_check_encrypt_br_dp_ks_ms_noise {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn noise_check_encrypt_br_dp_ks_ms_pfail<P>(params: P)
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

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let max_scalar_mul = sks.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result =
                encrypt_br_dp_ks_any_ms_pfail_helper(params, &cks, &sks, 0, max_scalar_mul);
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_parameterized_test!(noise_check_encrypt_br_dp_ks_ms_pfail {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
