use super::utils::noise_simulation::{
    NoiseSimulationDriftTechniqueKey, NoiseSimulationGlwe, NoiseSimulationLwe,
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
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, CarryModulus};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulus;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::ServerKey;
use crate::shortint::{Ciphertext, PaddingBit};
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
pub fn br_rerand_dp_ks_any_ms<
    InputCt,
    InputZeroRerand,
    KsKeyRerand,
    KsedZeroReRand,
    PBSResult,
    ReRandCt,
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
    input_zero_rerand: InputZeroRerand,
    ksk_rerand: &KsKeyRerand,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig,
    mod_switch_noise_reduction_key: Option<&DriftKey>,
    accumulator: &Accumulator,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    (InputCt, PBSResult),
    (InputZeroRerand, KsedZeroReRand),
    ReRandCt,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    Accumulator: AllocateLweBootstrapResult<Output = PBSResult, SideResources = Resources>,
    PBSKey: LweClassicFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>,
    KsKeyRerand: AllocateLweKeyswitchResult<Output = KsedZeroReRand, SideResources = Resources>
        + LweKeyswitch<InputZeroRerand, KsedZeroReRand, SideResources = Resources>,
    PBSResult: for<'a> LweUncorrelatedAdd<
        &'a KsedZeroReRand,
        Output = ReRandCt,
        SideResources = Resources,
    >,
    ReRandCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
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
    // BR to decomp
    let mut br_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk.lwe_classic_fft_pbs(&input, &mut br_result, accumulator, side_resources);

    // Ks the CPK encryption of 0 to be added to BR result
    let mut ksed_zero_rerand = ksk_rerand.allocate_lwe_keyswitch_result(side_resources);
    ksk_rerand.lwe_keyswitch(&input_zero_rerand, &mut ksed_zero_rerand, side_resources);

    // ReRand is done here
    let rerand_ct = br_result.lwe_uncorrelated_add(&ksed_zero_rerand, side_resources);

    // DP
    let dp_result = rerand_ct.scalar_mul(scalar, side_resources);

    let mut ks_result = ksk.allocate_lwe_keyswitch_result(side_resources);
    ksk.lwe_keyswitch(&dp_result, &mut ks_result, side_resources);

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

    (
        (input, br_result),
        (input_zero_rerand, ksed_zero_rerand),
        rerand_ct,
        dp_result,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}

fn encrypt_br_rerand_dp_ks_any_ms_inner_helper(
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

    let br_input_modulus_log = sks.br_input_modulus_log();
    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let ct = cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0);

    let id_lut = sks.generate_lookup_table(|x| x);

    // let (input, after_br, after_dp, after_ks, after_drift, after_ms)
    let (
        (input, after_br),
        (input_zero_rerand, after_ksed_zero_rerand),
        after_rerand,
        after_dp,
        after_ks,
        after_drift,
        after_ms,
    ) = br_rerand_dp_ks_any_ms(
        ct,
        sks,
        cpk_ct_zero_rerand,
        ksk_rerand,
        scalar_for_multiplication,
        sks,
        noise_simulation_modulus_switch_config,
        drift_key,
        &id_lut,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            let params = standard_atomic_pattern_client_key.parameters;
            let output_encoding = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };
            let large_lwe_secret_key = standard_atomic_pattern_client_key.large_lwe_secret_key();
            let small_lwe_secret_key = standard_atomic_pattern_client_key.small_lwe_secret_key();
            (
                DecryptionAndNoiseResult::new_from_lwe(
                    &input.as_lwe_64(),
                    &small_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_br.as_lwe_64(),
                    &large_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_dp.as_lwe_64(),
                    &large_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ks.as_lwe_64(),
                    &small_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &before_ms.as_lwe_64(),
                    &small_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ms.as_lwe_64(),
                    &small_lwe_secret_key,
                    msg,
                    &output_encoding,
                ),
            )
        }
        AtomicPatternClientKey::KeySwitch32(ks32_atomic_pattern_client_key) => {
            let msg_u32: u32 = msg.try_into().unwrap();
            let params = ks32_atomic_pattern_client_key.parameters;
            let small_key_encoding = ShortintEncoding {
                ciphertext_modulus: params.post_keyswitch_ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };
            let big_key_encoding = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };
            let large_lwe_secret_key = ks32_atomic_pattern_client_key.large_lwe_secret_key();
            let small_lwe_secret_key = ks32_atomic_pattern_client_key.small_lwe_secret_key();
            (
                DecryptionAndNoiseResult::new_from_lwe(
                    &input.as_lwe_32(),
                    &small_lwe_secret_key,
                    msg_u32,
                    &small_key_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_br.as_lwe_64(),
                    &large_lwe_secret_key,
                    msg,
                    &big_key_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_dp.as_lwe_64(),
                    &large_lwe_secret_key,
                    msg,
                    &big_key_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ks.as_lwe_32(),
                    &small_lwe_secret_key,
                    msg_u32,
                    &small_key_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &before_ms.as_lwe_32(),
                    &small_lwe_secret_key,
                    msg_u32,
                    &small_key_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ms.as_lwe_32(),
                    &small_lwe_secret_key,
                    msg_u32,
                    &small_key_encoding,
                ),
            )
        }
    }
}

fn encrypt_br_rerand_dp_ks_any_ms_noise_helper(
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
        encrypt_br_rerand_dp_ks_any_ms_inner_helper(
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

fn encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_br, _after_dp, _after_ks, _before_ms, after_ms) =
        encrypt_br_rerand_dp_ks_any_ms_inner_helper(
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
    let noise_simulation_ksk_rerand =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(todo!(
            "Manage rerand case with CPK + dedicated KSK params for rerand"
        ));
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk =
        NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);

    let noise_simulation_modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        noise_simulation_modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    match (noise_simulation_drift_key, drift_key) {
        (Some(noise_simulation_drift_key), Some(drift_key)) => {
            assert!(noise_simulation_drift_key.matches_actual_shortint_server_key(drift_key))
        }
        (None, None) => (),
        _ => panic!("Inconsistent Drift Key configuration"),
    }
    assert!(noise_simulation_bsk.matches_actual_shortint_server_key(&sks));

    let max_scalar_mul = sks.max_noise_level.get();

    let (
        (_input_sim, _after_br_sim),
        (_input_zero_rerand_sim, _after_ksed_zero_rerand_sim),
        _after_rerand_sim,
        _after_dp_sim,
        _after_ks_sim,
        _after_drift_sim,
        after_ms_sim,
    ) = {
        // Noiseless LWE already mod switched is the input of the AP for testing
        let noise_simulation_input = NoiseSimulationLwe::new(
            noise_simulation_bsk.input_lwe_dimension(),
            Variance(0.0),
            NoiseSimulationModulus::Other(1 << br_input_modulus_log.0),
        );
        let noise_simulation_input_zero_rerand = NoiseSimulationLwe::new(todo!(), todo!(), todo!());
        let noise_simulation_accumulator = NoiseSimulationGlwe::new(
            noise_simulation_bsk.output_glwe_size().to_glwe_dimension(),
            noise_simulation_bsk.output_polynomial_size(),
            Variance(0.0),
            noise_simulation_bsk.modulus(),
        );
        br_rerand_dp_ks_any_ms(
            noise_simulation_input,
            &noise_simulation_bsk,
            noise_simulation_input_zero_rerand,
            &noise_simulation_ksk_rerand,
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
    let sample_input = cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0);

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (
            (_input, _after_br),
            (_input_zero_rerand, _after_ksed_zero_rerand),
            _after_rerand,
            _after_dp,
            _after_ks,
            _before_ms,
            after_ms,
        ) = br_rerand_dp_ks_any_ms(
            sample_input,
            &sks,
            cpk_zero_sample_input,
            ksk_rerand,
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
                    encrypt_br_rerand_dp_ks_any_ms_noise_helper(
                        params,
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
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
});
