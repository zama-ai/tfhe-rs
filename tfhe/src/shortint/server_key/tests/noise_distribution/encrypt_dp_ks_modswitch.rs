use super::should_use_single_key_debug;
use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{mean_and_variance_check, DecryptionAndNoiseResult};
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
use crate::shortint::parameters::AtomicPatternParameters;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::ServerKey;
use rayon::prelude::*;

fn dp_ks_modswitch<InputCt, ScalarMulResult, KsResult, MsResult, DPScalar, KsKey, Resources>(
    input: &InputCt,
    scalar: DPScalar,
    ksk: &KsKey,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> MsResult
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateKeyswtichResult<Output = KsResult, SideResources = Resources>
        + Keyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
    // We need to be able to allocate the result of mod switching the KsResult and mod switch it
    KsResult: AllocateClassicPBSModSwitchResult<Output = MsResult, SideResources = Resources>
        + ClassicPBSModSwitch<MsResult, SideResources = Resources>,
{
    let after_dp = input.scalar_mul(scalar, side_resources);
    let mut ks_result = ksk.allocate_keyswitch_result(side_resources);
    ksk.keyswitch(&after_dp, &mut ks_result, side_resources);
    let mut ms_result = ks_result.allocate_classic_mod_switch_result(side_resources);
    ks_result.classic_mod_switch(br_input_modulus_log, &mut ms_result, side_resources);

    ms_result
}

fn encrypt_dp_ks_ms_inner_helper(
    params: AtomicPatternParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
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

    let (ksk, br_input_modulus_log) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            &standard_atomic_pattern_server_key.key_switching_key,
            standard_atomic_pattern_server_key
                .bootstrapping_key
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
        ),
        AtomicPatternServerKey::KeySwitch32(_) => {
            todo!()
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let ct = cks.unchecked_encrypt(msg);

    let res = dp_ks_modswitch(
        &ct.ct,
        scalar_for_multiplication,
        ksk,
        br_input_modulus_log,
        &mut (),
    );

    let output_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    match &cks.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            DecryptionAndNoiseResult::new(
                &res,
                &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                msg,
                output_encoding.delta(),
                output_encoding.cleartext_space(),
            )
        }
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    }
}

fn noise_check_shortint_encrypt_dp_ks_ms<P>(params: P)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let noise_simulation_ksk = NoiseSimulationLweKsk::new_from_atomic_pattern_parameters(params);

    let br_input_modulus_log = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key));
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

    let noise_simulation_result = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks, 0);
        dp_ks_modswitch(
            &noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            br_input_modulus_log,
            &mut (),
        )
    };

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let expected_lwe_dimension_out = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            let res = dp_ks_modswitch(
                &cks.encrypt(0).ct,
                max_scalar_mul,
                &standard_atomic_pattern_server_key.key_switching_key,
                br_input_modulus_log,
                &mut (),
            );
            res.lwe_size().to_lwe_dimension()
        }
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
            let res = dp_ks_modswitch(
                &cks.encrypt(0).ct,
                max_scalar_mul,
                &ks32_atomic_pattern_server_key.key_switching_key,
                br_input_modulus_log,
                &mut (),
            );
            res.lwe_size().to_lwe_dimension()
        }
        _ => unimplemented!(),
    };

    assert_eq!(
        noise_simulation_result.lwe_dimension(),
        expected_lwe_dimension_out
    );

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples = vec![];

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let res = encrypt_dp_ks_ms_inner_helper(params, &cks, &sks, 0, max_scalar_mul);
                match res {
                    DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise.value,
                    DecryptionAndNoiseResult::DecryptionFailed => panic!("Incorrect decryption"),
                }
            })
            .collect();

        noise_samples.extend(current_noise_samples);
    }

    assert!(mean_and_variance_check(
        &noise_samples,
        "after_ms",
        0.0,
        noise_simulation_result.variance(),
        params.lwe_noise_distribution(),
        noise_simulation_result.lwe_dimension(),
        noise_simulation_result.modulus().as_f64()
    ));
}

create_parameterized_test!(noise_check_shortint_encrypt_dp_ks_ms {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
