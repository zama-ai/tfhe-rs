use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, CarryModulus};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::ServerKey;
use rayon::prelude::*;

pub fn any_ms<InputCt, DriftTechniqueResult, MsResult, DriftKey, Resources>(
    input: &InputCt,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (Option<DriftTechniqueResult>, MsResult)
where
    InputCt: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
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
            InputCt,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    match modulus_switch_configuration {
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction(
            mod_switch_noise_reduction_key,
        ) => {
            let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key
                .allocate_drift_technique_standard_mod_switch_result(side_resources);
            mod_switch_noise_reduction_key.drift_technique_and_standard_mod_switch(
                br_input_modulus_log,
                input,
                &mut drift_technique_result,
                &mut ms_result,
                side_resources,
            );

            (Some(drift_technique_result), ms_result)
        }
        NoiseSimulationModulusSwitchConfig::Standard => {
            let mut ms_result = input.allocate_standard_mod_switch_result(side_resources);
            input.standard_mod_switch(br_input_modulus_log, &mut ms_result, side_resources);

            (None, ms_result)
        }
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => {
            let mut ms_result =
                input.allocate_centered_binary_shifted_standard_mod_switch_result(side_resources);
            input.centered_binary_shifted_and_standard_mod_switch(
                br_input_modulus_log,
                &mut ms_result,
                side_resources,
            );

            (None, ms_result)
        }
    }
}

pub fn dp_ks_any_ms<
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    DPScalar,
    KsKey,
    DriftKey,
    Resources,
>(
    input: InputCt,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
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
    let after_dp = input.scalar_mul(scalar, side_resources);
    let mut ks_result = ksk.allocate_lwe_keyswitch_result(side_resources);
    ksk.lwe_keyswitch(&after_dp, &mut ks_result, side_resources);

    let (drift_technique_result, ms_result) = any_ms(
        &ks_result,
        modulus_switch_configuration,
        br_input_modulus_log,
        side_resources,
    );

    (
        input,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint
fn sanity_check_encrypt_dp_ks_pbs<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let max_scalar_mul = sks.max_noise_level.get();

    let id_lut = sks.generate_lookup_table(|x| x);

    let br_input_modulus_log = sks.br_input_modulus_log();
    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();

    for _ in 0..10 {
        let input_zero = cks.encrypt(0);
        let input_zero_as_lwe = DynLwe::U64(input_zero.ct.clone());

        let (_input, _after_dp, _after_ks, _before_ms, after_ms) = dp_ks_any_ms(
            input_zero_as_lwe,
            max_scalar_mul,
            &sks,
            modulus_switch_config,
            br_input_modulus_log,
            &mut (),
        );

        // Complete the AP by computing the PBS to match shortint
        let mut pbs_result = id_lut.allocate_lwe_bootstrap_result(&mut ());
        sks.lwe_classic_fft_pbs(&after_ms, &mut pbs_result, &id_lut, &mut ());

        let mut shortint_res =
            sks.unchecked_scalar_mul(&input_zero, max_scalar_mul.try_into().unwrap());
        sks.apply_lookup_table_assign(&mut shortint_res, &id_lut);

        assert_eq!(pbs_result.as_lwe_64(), shortint_res.ct.as_view());
    }
}

create_parameterized_test!(sanity_check_encrypt_dp_ks_pbs {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
});

fn encrypt_dp_ks_any_ms_inner_helper(
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
    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();

    let ct = DynLwe::U64(cks.unchecked_encrypt(msg).ct);

    let (input, after_dp, after_ks, after_drift, after_ms) = dp_ks_any_ms(
        ct,
        scalar_for_multiplication,
        sks,
        modulus_switch_config,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
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
                    &input.as_lwe_64(),
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

fn encrypt_dp_ks_any_ms_noise_helper(
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
) {
    let (input, after_dp, after_ks, before_ms, after_ms) = encrypt_dp_ks_any_ms_inner_helper(
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

fn encrypt_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_dp, _after_ks, _before_ms, after_ms) = encrypt_dp_ks_any_ms_inner_helper(
        params,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    after_ms
}

fn noise_check_encrypt_dp_ks_ms_noise<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));

    let max_scalar_mul = sks.max_noise_level.get();

    let (_input_sim, _after_dp_sim, _after_ks_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks, 0);
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
    let sample_input = DynLwe::U64(cks.encrypt(0).ct);

    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (_input, _after_dp, _after_ks, _after_drift, after_ms) = dp_ks_any_ms(
            sample_input,
            max_scalar_mul,
            &sks,
            modulus_switch_config,
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
                let (_input, _after_dp, _after_ks, before_ms, after_ms) =
                    encrypt_dp_ks_any_ms_noise_helper(params, &cks, &sks, 0, max_scalar_mul);
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

create_parameterized_test!(noise_check_encrypt_dp_ks_ms_noise {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
});

fn noise_check_encrypt_dp_ks_ms_pfail<P>(params: P)
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
                encrypt_dp_ks_any_ms_pfail_helper(params, &cks, &sks, 0, max_scalar_mul);
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_parameterized_test!(noise_check_encrypt_dp_ks_ms_pfail {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
});
