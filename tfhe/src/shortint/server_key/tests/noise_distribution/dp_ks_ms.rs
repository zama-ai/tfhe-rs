use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, CarryModulus};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::{ServerKey, ShortintBootstrappingKey};
use rayon::prelude::*;

pub fn dp_ks_ms<
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
    mod_switch_noise_reduction_key: &DriftKey,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateKeyswtichResult<Output = KsResult, SideResources = Resources>
        + Keyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
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
    let mut ks_result = ksk.allocate_keyswitch_result(side_resources);
    ksk.keyswitch(&after_dp, &mut ks_result, side_resources);
    let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key
        .allocate_drift_technique_standard_mod_switch_result(side_resources);
    mod_switch_noise_reduction_key.drift_technique_and_standard_mod_switch(
        br_input_modulus_log,
        &ks_result,
        &mut drift_technique_result,
        &mut ms_result,
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

#[allow(clippy::too_many_arguments)]
fn dp_ks_classic_pbs<
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PbsResult,
    DPScalar,
    KsKey,
    DriftKey,
    Bsk,
    Accumulator,
    Resources,
>(
    input: InputCt,
    scalar: DPScalar,
    ksk: &KsKey,
    mod_switch_noise_reduction_key: &DriftKey,
    bsk: &Bsk,
    br_input_modulus_log: CiphertextModulusLog,
    accumulator: &Accumulator,
    side_resources: &mut Resources,
) -> (
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PbsResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateKeyswtichResult<Output = KsResult, SideResources = Resources>
        + Keyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
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
    // The accumulator has the information about the output size and modulus, therefore it is the
    // one to allocate the blind rotation result
    Accumulator: AllocateBootstrapResult<Output = PbsResult, SideResources = Resources>,
    // We need to be able to apply the PBS
    Bsk: StandardFftBootstrap<MsResult, PbsResult, Accumulator, SideResources = Resources>,
{
    let (input, after_dp, ks_result, drift_technique_result, ms_result) = dp_ks_ms(
        input,
        scalar,
        ksk,
        mod_switch_noise_reduction_key,
        br_input_modulus_log,
        side_resources,
    );

    let mut pbs_result = accumulator.allocate_bootstrap_result(side_resources);
    bsk.standard_fft_pbs(&ms_result, &mut pbs_result, accumulator, side_resources);
    (
        input,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
        pbs_result,
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

    match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            let ksk = &standard_atomic_pattern_server_key.key_switching_key;
            let bsk = &standard_atomic_pattern_server_key.bootstrapping_key;
            let (fbsk, drift_key) = match bsk {
                ShortintBootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                } => (
                    bsk,
                    modulus_switch_noise_reduction_key
                        .modulus_switch_noise_reduction_key()
                        .unwrap(),
                ),
                ShortintBootstrappingKey::MultiBit { .. } => todo!(),
            };

            let br_input_modulus_log = fbsk.polynomial_size().to_blind_rotation_input_modulus_log();

            for _ in 0..10 {
                let input_zero = cks.encrypt(0);
                let input_zero_as_lwe = input_zero.ct.clone();

                let (_input, _after_dp, _after_ks, _after_drift, _after_ms, after_pbs) =
                    dp_ks_classic_pbs(
                        input_zero_as_lwe,
                        max_scalar_mul,
                        ksk,
                        drift_key,
                        fbsk,
                        br_input_modulus_log,
                        &id_lut.acc,
                        &mut (),
                    );

                let mut shortint_res =
                    sks.unchecked_scalar_mul(&input_zero, max_scalar_mul.try_into().unwrap());
                sks.apply_lookup_table_assign(&mut shortint_res, &id_lut);

                assert_eq!(after_pbs.as_view(), shortint_res.ct.as_view());
            }
        }
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => {
            todo!();
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    }
}

create_parameterized_test!(sanity_check_encrypt_dp_ks_pbs {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn encrypt_dp_ks_ms_inner_helper(
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

    let (ksk, drift_key, br_input_modulus_log) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            let drift_key = standard_atomic_pattern_server_key
                .bootstrapping_key
                .modulus_switch_configuration()
                .unwrap()
                .modulus_switch_noise_reduction_key()
                .unwrap();

            (
                &standard_atomic_pattern_server_key.key_switching_key,
                drift_key,
                standard_atomic_pattern_server_key
                    .bootstrapping_key
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log(),
            )
        }
        AtomicPatternServerKey::KeySwitch32(_) => {
            todo!()
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let ct = cks.unchecked_encrypt(msg);

    let (input, after_dp, after_ks, after_drift, after_ms) = dp_ks_ms(
        ct.ct,
        scalar_for_multiplication,
        ksk,
        drift_key,
        br_input_modulus_log,
        &mut (),
    );

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new(
                &input,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new(
                &after_dp,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new(
                &after_ks,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new(
                &after_drift,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
            DecryptionAndNoiseResult::new(
                &after_ms,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                &output_encoding,
            ),
        ),
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    }
}

fn encrypt_dp_ks_ms_noise_helper(
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
    let (input, after_dp, after_ks, after_drift, after_ms) = encrypt_dp_ks_ms_inner_helper(
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
        after_drift
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
    )
}

fn encrypt_dp_ks_ms_pfail_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (_input, _after_dp, _after_ks, _after_drift, after_ms) = encrypt_dp_ks_ms_inner_helper(
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

    let noise_simulation_ksk = NoiseSimulationLweKsk::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);

    let br_input_modulus_log = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key));

            let drift_key = standard_atomic_pattern_server_key
                .bootstrapping_key
                .modulus_switch_configuration()
                .unwrap()
                .modulus_switch_noise_reduction_key()
                .unwrap();

            assert!(noise_simulation_drift_key.matches_actual_drift_key(drift_key));

            standard_atomic_pattern_server_key
                .bootstrapping_key
                .polynomial_size()
                .to_blind_rotation_input_modulus_log()
        }
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&ks32_atomic_pattern_server_key.key_switching_key));
            ks32_atomic_pattern_server_key
                .bootstrapping_key
                .polynomial_size()
                .to_blind_rotation_input_modulus_log()
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let max_scalar_mul = sks.max_noise_level.get();

    let (_input_sim, _after_dp_sim, _after_ks_sim, _after_drift_sim, after_ms_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks, 0);
        dp_ks_ms(
            noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            &noise_simulation_drift_key,
            br_input_modulus_log,
            &mut (),
        )
    };

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            let drift_key = standard_atomic_pattern_server_key
                .bootstrapping_key
                .modulus_switch_configuration()
                .unwrap()
                .modulus_switch_noise_reduction_key()
                .unwrap();

            let (_input, _after_dp, _after_ks, _after_drift, after_ms) = dp_ks_ms(
                cks.encrypt(0).ct,
                max_scalar_mul,
                &standard_atomic_pattern_server_key.key_switching_key,
                drift_key,
                br_input_modulus_log,
                &mut (),
            );
            (
                after_ms.lwe_size().to_lwe_dimension(),
                after_ms.ciphertext_modulus().raw_modulus_float(),
            )
        }
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
            let drift_key = ks32_atomic_pattern_server_key
                .bootstrapping_key
                .modulus_switch_configuration()
                .unwrap()
                .modulus_switch_noise_reduction_key()
                .unwrap();

            let (_input, _after_dp, _after_ks, _after_drift, after_ms) = dp_ks_ms(
                cks.encrypt(0).ct,
                max_scalar_mul,
                &ks32_atomic_pattern_server_key.key_switching_key,
                drift_key,
                br_input_modulus_log,
                &mut (),
            );
            (
                after_ms.lwe_size().to_lwe_dimension(),
                after_ms.ciphertext_modulus().raw_modulus_float(),
            )
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    assert_eq!(after_ms_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_drift = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let (current_noise_sample_after_drift, current_noise_samples_after_ms): (Vec<_>, Vec<_>) =
            (0..sample_count_per_msg)
                .into_par_iter()
                .map(|_| {
                    let (_input, _after_dp, _after_ks, after_drift, after_ms) =
                        encrypt_dp_ks_ms_noise_helper(params, &cks, &sks, 0, max_scalar_mul);
                    (after_drift.value, after_ms.value)
                })
                .unzip();

        noise_samples_after_drift.extend(current_noise_sample_after_drift);
        noise_samples_after_ms.extend(current_noise_samples_after_ms);
    }

    let after_drift_normality = normality_check(&noise_samples_after_drift, "after drift", 0.01);

    let after_ms_is_ok = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        0.0,
        after_ms_sim.variance(),
        params.lwe_noise_distribution(),
        after_ms_sim.lwe_dimension(),
        after_ms_sim.modulus().as_f64(),
    );

    assert!(after_drift_normality.null_hypothesis_is_valid && after_ms_is_ok);
}

create_parameterized_test!(noise_check_encrypt_dp_ks_ms_noise {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
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
                encrypt_dp_ks_ms_pfail_helper(params, &cks, &sks, 0, max_scalar_mul);
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_parameterized_test!(noise_check_encrypt_dp_ks_ms_pfail {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
