use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus,
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::{ServerKey, ShortintBootstrappingKey};
use rayon::prelude::*;

fn dp_ks_classic_pbs128<
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
    mod_switch_noise_reduction_key_128: &DriftKey,
    bsk_128: &Bsk,
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
    DriftKey: AllocateDriftTechniqueClassicModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DrifTechniqueClassicModSwitch<
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
    // The accumulator has the information about the output size and modulus, therefore it is the
    // one to allocate the blind rotation result
    Accumulator: AllocateBlindRotationResult<Output = PbsResult, SideResources = Resources>,
    // We need to be able to apply the PBS
    Bsk: ClassicFft128Bootstrap<MsResult, PbsResult, Accumulator, SideResources = Resources>,
{
    let after_dp = input.scalar_mul(scalar, side_resources);
    let mut ks_result = ksk.allocate_keyswitch_result(side_resources);
    ksk.keyswitch(&after_dp, &mut ks_result, side_resources);
    let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key_128
        .allocate_drift_technique_classic_mod_switch_result(side_resources);
    mod_switch_noise_reduction_key_128.drift_technique_and_classic_mod_switch(
        br_input_modulus_log,
        &ks_result,
        &mut drift_technique_result,
        &mut ms_result,
        side_resources,
    );

    let mut pbs_result = accumulator.allocated_blind_rotation_result(side_resources);
    bsk_128.classic_fft_128_pbs(&ms_result, &mut pbs_result, accumulator, side_resources);
    (
        input,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
        pbs_result,
    )
}

fn encrypt_dp_ks_classic_pbs128_inner_helper(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &NoiseSquashingKey,
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
    let thread_private_noise_squashing_key;
    let thread_noise_squashing_key;
    let (cks, sks, noise_squashing_private_key, noise_squashing_key) =
        if should_use_single_key_debug() {
            (
                single_cks,
                single_sks,
                single_noise_squashing_private_key,
                single_noise_squashing_key,
            )
        } else {
            thread_cks = engine.new_client_key(params);
            thread_sks = engine.new_server_key(&thread_cks);
            thread_private_noise_squashing_key =
                NoiseSquashingPrivateKey::new(noise_squashing_params);
            thread_noise_squashing_key =
                NoiseSquashingKey::new(&thread_cks, &thread_private_noise_squashing_key);

            (
                &thread_cks,
                &thread_sks,
                &thread_private_noise_squashing_key,
                &thread_noise_squashing_key,
            )
        };

    let ksk = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            &standard_atomic_pattern_server_key.key_switching_key
        }
        AtomicPatternServerKey::KeySwitch32(_) => {
            todo!()
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let ct = cks.unchecked_encrypt(msg);

    let drift_key = noise_squashing_key
        .modulus_switch_noise_reduction_key()
        .unwrap();

    let bsk_128 = noise_squashing_key.bootstrapping_key();
    let bsk_polynomial_size = bsk_128.polynomial_size();
    let bsk_glwe_size = bsk_128.glwe_size();
    let br_input_modulus_log = bsk_128
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus,
        message_modulus: noise_squashing_params.message_modulus,
        carry_modulus: noise_squashing_params.carry_modulus,
        padding_bit: PaddingBit::Yes,
    };

    let id_lut = generate_programmable_bootstrap_glwe_lut(
        bsk_polynomial_size,
        bsk_glwe_size,
        u128_encoding.cleartext_space().try_into().unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let (input, after_dp, after_ks, after_drift, after_ms, after_pbs128) = dp_ks_classic_pbs128(
        ct.ct,
        scalar_for_multiplication,
        ksk,
        drift_key,
        bsk_128,
        br_input_modulus_log,
        &id_lut,
        &mut (),
    );

    let u64_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
            DecryptionAndNoiseResult::new(
                &input,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                u64_encoding.delta(),
                u64_encoding.cleartext_space(),
            ),
            DecryptionAndNoiseResult::new(
                &after_dp,
                &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                msg,
                u64_encoding.delta(),
                u64_encoding.cleartext_space(),
            ),
            DecryptionAndNoiseResult::new(
                &after_ks,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                u64_encoding.delta(),
                u64_encoding.cleartext_space(),
            ),
            DecryptionAndNoiseResult::new(
                &after_drift,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                u64_encoding.delta(),
                u64_encoding.cleartext_space(),
            ),
            DecryptionAndNoiseResult::new(
                &after_ms,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                u64_encoding.delta(),
                u64_encoding.cleartext_space(),
            ),
            DecryptionAndNoiseResult::new(
                &after_pbs128,
                &noise_squashing_private_key.post_noise_squashing_lwe_secret_key(),
                msg.into(),
                u128_encoding.delta(),
                u128_encoding.cleartext_space(),
            ),
        ),
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    }
}

fn encrypt_dp_ks_classic_pbs128_noise_helper(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &NoiseSquashingKey,
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
    let (input, after_dp, after_ks, after_drift, after_ms, after_pbs128) =
        encrypt_dp_ks_classic_pbs128_inner_helper(
            params,
            noise_squashing_params,
            single_cks,
            single_sks,
            single_noise_squashing_private_key,
            single_noise_squashing_key,
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
        after_pbs128
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
    )
}

fn noise_check_encrypt_dp_ks_classic_pbs128_noise<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
) where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

    let noise_simulation_ksk = NoiseSimulationLweKsk::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk128 =
        NoiseSimulationLweClassicBsk128::new_from_parameters(params, noise_squashing_params);

    assert!(noise_simulation_bsk128.matches_actual_bsk(noise_squashing_key.bootstrapping_key()));

    let br_input_modulus_log = noise_squashing_key
        .bootstrapping_key()
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key));
        }
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&ks32_atomic_pattern_server_key.key_switching_key));
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let max_scalar_mul = sks.max_noise_level.get();

    let noise_simulation_accumulator = NoiseSimulationGlwe::new(
        noise_simulation_bsk128
            .output_glwe_size()
            .to_glwe_dimension(),
        noise_simulation_bsk128.output_polynomial_size(),
        Variance(0.0),
        noise_simulation_bsk128.modulus(),
    );

    let (
        _input_sim,
        _after_dp_sim,
        _after_ks_sim,
        _after_drift_sim,
        _after_ms_sim,
        after_pbs128_sim,
    ) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks, 0);
        dp_ks_classic_pbs128(
            noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            &noise_simulation_drift_key,
            &noise_simulation_bsk128,
            br_input_modulus_log,
            &noise_simulation_accumulator,
            &mut (),
        )
    };

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let expected_lwe_dimension_out = noise_squashing_key
        .bootstrapping_key()
        .output_lwe_dimension();
    let expected_modulus_f64_out = noise_squashing_key
        .output_ciphertext_modulus()
        .raw_modulus_float();

    assert_eq!(after_pbs128_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(
        after_pbs128_sim.modulus().as_f64(),
        expected_modulus_f64_out
    );

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_pbs128 = vec![];

    let sample_count_per_msg = 10;

    for _ in 0..cleartext_modulus {
        let current_noise_samples_after_pbs128: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let (_input, _after_dp, _after_ks, _after_drift, _after_ms, after_pbs128) =
                    encrypt_dp_ks_classic_pbs128_noise_helper(
                        params,
                        noise_squashing_params,
                        &cks,
                        &sks,
                        &noise_squashing_private_key,
                        &noise_squashing_key,
                        0,
                        max_scalar_mul,
                    );
                after_pbs128.value
            })
            .collect();

        noise_samples_after_pbs128.extend(current_noise_samples_after_pbs128);
    }

    let after_pbs128_is_ok = mean_and_variance_check(
        &noise_samples_after_pbs128,
        "after_pbs128",
        0.0,
        after_pbs128_sim.variance(),
        noise_squashing_params.glwe_noise_distribution,
        after_pbs128_sim.lwe_dimension(),
        after_pbs128_sim.modulus().as_f64(),
    );

    assert!(after_pbs128_is_ok);
}

#[test]
fn test_noise_check_encrypt_dp_ks_classic_pbs128_noise_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    noise_check_encrypt_dp_ks_classic_pbs128_noise(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
