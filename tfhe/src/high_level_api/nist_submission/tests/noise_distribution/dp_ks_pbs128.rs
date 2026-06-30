use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::commons::dispersion::Variance;
use crate::nist_submission::NIST_META_PARAMS_2_2;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::{AtomicPatternParameters, MetaParameters};
use crate::shortint::server_key::tests::noise_distribution::dp_ks_pbs128_packingks::dp_ks_any_ms_standard_pbs128;
use crate::shortint::server_key::tests::noise_distribution::should_use_single_key_debug;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationGenericBootstrapKey128, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::TestJsonGuard;
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, noise_check, DecryptionAndNoiseResult, NoiseSample,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::this_function_name;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_pbs128_inner_helper(
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
    let thread_noise_squashing_private_key;
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
            thread_noise_squashing_private_key =
                NoiseSquashingPrivateKey::new(noise_squashing_params);
            thread_noise_squashing_key =
                NoiseSquashingKey::new(&thread_cks, &thread_noise_squashing_private_key);

            (
                &thread_cks,
                &thread_sks,
                &thread_noise_squashing_private_key,
                &thread_noise_squashing_key,
            )
        };

    let modulus_switch_config = noise_squashing_key.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = noise_squashing_key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let id_lut = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.polynomial_size(),
        noise_squashing_key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let input = DynLwe::U64(cks.encrypt(msg).ct);

    let (input, after_dp, after_ks, after_drift, after_ms, after_pbs128) =
        dp_ks_any_ms_standard_pbs128(
            input,
            scalar_for_multiplication,
            sks,
            modulus_switch_config,
            noise_squashing_key,
            br_input_modulus_log,
            &id_lut,
            &mut (),
        );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

    let large_lwe_secret_key_dyn = cks.large_lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    (
        DecryptionAndNoiseResult::new_from_dyn_lwe(&input, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_dp, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_ks, &small_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(before_ms, &small_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
            &after_ms,
            &small_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_lwe(
            &after_pbs128,
            &noise_squashing_private_key.post_noise_squashing_lwe_secret_key(),
            msg.into(),
            &u128_encoding,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_pbs128_noise_helper(
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
    let (input, after_dp, after_ks, before_ms, after_ms, after_pbs128) =
        encrypt_dp_ks_pbs128_inner_helper(
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
        before_ms
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

fn noise_check_encrypt_dp_ks_pbs128_noise(meta_params: MetaParameters, filename_suffix: &str) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();

    let (params, noise_squashing_params) = {
        let meta_noise_squashing_params = meta_params.noise_squashing_parameters.unwrap();
        (
            meta_params
                .compute_parameters
                .with_deterministic_execution(),
            meta_noise_squashing_params
                .parameters
                .with_deterministic_execution(),
        )
    };

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk128 =
        NoiseSimulationGenericBootstrapKey128::new_from_parameters(params, noise_squashing_params);

    let modulus_switch_config = noise_squashing_key.noise_simulation_modulus_switch_config();

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_noise_squashing_modulus_switch_config(modulus_switch_config));
    assert!(
        noise_simulation_bsk128.matches_actual_shortint_noise_squashing_key(&noise_squashing_key)
    );

    let br_input_modulus_log = noise_squashing_key.br_input_modulus_log();
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
        dp_ks_any_ms_standard_pbs128(
            noise_simulation,
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_bsk128,
            br_input_modulus_log,
            &noise_simulation_accumulator,
            &mut (),
        )
    };

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_pbs128 = vec![];

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let current_noise_samples_after_pbs128: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let (_input, _after_dp, _after_ks, _before_ms, _after_ms, after_pbs128) =
                    encrypt_dp_ks_pbs128_noise_helper(
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

    let mean_variance_result = mean_and_variance_check(
        &noise_samples_after_pbs128,
        "after_pbs128",
        0.0,
        after_pbs128_sim.variance(),
        noise_squashing_params.glwe_noise_distribution(),
        after_pbs128_sim.lwe_dimension(),
        after_pbs128_sim.modulus().as_f64(),
    );

    noise_check(&guard, mean_variance_result, None);
}

create_parameterized_stringified_test!(noise_check_encrypt_dp_ks_pbs128_noise {
    NIST_META_PARAMS_2_2,
});
