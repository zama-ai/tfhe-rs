use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::traits::container::Container;
use crate::nist_submission::NIST_META_PARAMS_2_2;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyView};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind, MetaParameters,
    ReRandomizationParameters, ShortintCompactCiphertextListCastingMode,
};
use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::shortint::server_key::tests::noise_distribution::br_rerand_dp_ks_ms::br_rerand_dp_ks_any_ms;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationGenericBootstrapKey, NoiseSimulationGlwe, NoiseSimulationLwe,
    NoiseSimulationLweKeyswitchKey, NoiseSimulationModulus, NoiseSimulationModulusSwitchConfig,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::TestJsonGuard;
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, noise_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::this_function_name;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_inner_helper<C>(
    params: AtomicPatternParameters,
    re_rand_parameters: ReRandomizationParameters,
    single_cpk_private_key: &CompactPrivateKey<C>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: Option<&KeySwitchingKeyView<'_>>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    (DecryptionAndNoiseResult, DecryptionAndNoiseResult),
    (DecryptionAndNoiseResult, Option<DecryptionAndNoiseResult>),
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
)
where
    C: Container<Element = u64>,
{
    let mut engine = ShortintEngine::new();
    let thread_cpk_private_key;
    let thread_cpk_private_key_view;
    let thread_cpk;
    let thread_ksk_rerand_builder;
    let thread_ksk_rerand;
    let thread_cks;
    let thread_sks;
    let (cpk_private_key, cpk, ksk_rerand, cks, sks) = if should_use_single_key_debug() {
        (
            single_cpk_private_key.as_view(),
            single_cpk,
            single_ksk_rerand,
            single_cks,
            single_sks,
        )
    } else {
        let cpk_params = single_cpk_private_key.parameters();

        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        match re_rand_parameters {
            ReRandomizationParameters::LegacyDedicatedCPKWithKeySwitch { rerand_ksk_params } => {
                thread_cpk_private_key =
                    CompactPrivateKey::new_with_engine(cpk_params, &mut engine);
                thread_cpk_private_key_view = thread_cpk_private_key.as_view();

                thread_ksk_rerand_builder = KeySwitchingKeyBuildHelper::new_with_engine(
                    (&thread_cpk_private_key, None),
                    (&thread_cks, &thread_sks),
                    rerand_ksk_params,
                    &mut engine,
                );
                thread_ksk_rerand = Some(thread_ksk_rerand_builder.as_key_switching_key_view());
            }
            ReRandomizationParameters::DerivedCPKWithoutKeySwitch => {
                thread_cpk_private_key_view = (&thread_cks).try_into().unwrap();
                thread_ksk_rerand = None;
            }
        }

        thread_cpk = CompactPublicKey::new_with_engine(&thread_cpk_private_key_view, &mut engine);

        (
            thread_cpk_private_key_view,
            &thread_cpk,
            thread_ksk_rerand.as_ref(),
            &thread_cks,
            &thread_sks,
        )
    };

    let br_input_modulus_log = sks.br_input_modulus_log();
    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();

    // NIST has no compression/decompression: the BR input is a noiseless LWE at the compute BR
    // input modulus (post-KS/post-MS), and the accumulator is the compute-side identity LUT.
    let ct = cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, msg);

    let cpk_ct_zero_rerand = {
        let compact_list =
            cpk.encrypt_iter_with_modulus(core::iter::once(0), cpk.parameters.message_modulus.0);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let id_lut = sks.generate_lookup_table(|x| x);

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
        modulus_switch_config,
        &id_lut,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

    let cpk_lwe_secret_key_dyn = cpk_private_key.lwe_secret_key_as_dyn();
    let large_lwe_secret_key_dyn = cks.large_lwe_secret_key_as_dyn();
    let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    (
        (
            DecryptionAndNoiseResult::new_from_dyn_lwe(&input, &small_lwe_secret_key_dyn, msg),
            DecryptionAndNoiseResult::new_from_dyn_lwe(&after_br, &large_lwe_secret_key_dyn, msg),
        ),
        (
            DecryptionAndNoiseResult::new_from_dyn_lwe(
                &input_zero_rerand,
                &cpk_lwe_secret_key_dyn,
                msg,
            ),
            after_ksed_zero_rerand
                .as_ref()
                .map(|after_ksed_zero_rerand| {
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        after_ksed_zero_rerand,
                        &large_lwe_secret_key_dyn,
                        msg,
                    )
                }),
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_rerand, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_dp, &large_lwe_secret_key_dyn, msg),
        DecryptionAndNoiseResult::new_from_dyn_lwe(&after_ks, &small_lwe_secret_key_dyn, msg),
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
fn encrypt_br_rerand_dp_ks_any_ms_noise_helper<C>(
    params: AtomicPatternParameters,
    re_rand_parameters: ReRandomizationParameters,
    single_cpk_private_key: &CompactPrivateKey<C>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: Option<&KeySwitchingKeyView<'_>>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    (NoiseSample, NoiseSample),
    (NoiseSample, Option<NoiseSample>),
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
)
where
    C: Container<Element = u64>,
{
    let (
        (input, after_br),
        (input_zero_rerand, after_ksed_zero_rerand),
        after_rerand,
        after_dp,
        after_ks,
        before_ms,
        after_ms,
    ) = encrypt_br_rerand_dp_ks_any_ms_inner_helper(
        params,
        re_rand_parameters,
        single_cpk_private_key,
        single_cpk,
        single_ksk_rerand,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    (
        (
            input
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
            after_br
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
        ),
        (
            input_zero_rerand
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
            after_ksed_zero_rerand.map(|after_ksed_zero_rerand| {
                after_ksed_zero_rerand
                    .get_noise_if_decryption_was_correct()
                    .expect("Decryption Failed")
            }),
        ),
        after_rerand
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_pfail_helper<C>(
    params: AtomicPatternParameters,
    re_rand_parameters: ReRandomizationParameters,
    single_cpk_private_key: &CompactPrivateKey<C>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: Option<&KeySwitchingKeyView<'_>>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult
where
    C: Container<Element = u64>,
{
    let (
        (_input, _after_br),
        (_input_zero_rerand, _after_ksed_zero_rerand),
        _after_rerand,
        _after_dp,
        _after_ks,
        _before_ms,
        after_ms,
    ) = encrypt_br_rerand_dp_ks_any_ms_inner_helper(
        params,
        re_rand_parameters,
        single_cpk_private_key,
        single_cpk,
        single_ksk_rerand,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    after_ms
}

fn noise_check_encrypt_br_rerand_dp_ks_ms_noise(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (compute_params, re_rand_parameters) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();

        (
            compute_params,
            meta_params
                .rerandomization_parameters()
                .expect("This test requires rerand to be available in parameters"),
        )
    };

    let cks = ClientKey::new(compute_params);
    let sks = ServerKey::new(&cks);
    let compact_private_key;

    // Create private key for the CPK depending on configuration
    let (cpk_private_key, rerand_ksk_params) = match re_rand_parameters {
        ReRandomizationParameters::LegacyDedicatedCPKWithKeySwitch { rerand_ksk_params } => {
            let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
            // To avoid the expand logic of shortint which would force a keyswitch + LUT eval
            // after expand
            let cpk_params = {
                let mut cpk_params = dedicated_cpk_params.pke_params;
                cpk_params.expansion_kind =
                    CompactCiphertextListExpansionKind::NoCasting(compute_params.atomic_pattern());
                cpk_params
            };

            compact_private_key = CompactPrivateKey::new(cpk_params);
            (compact_private_key.as_view(), Some(rerand_ksk_params))
        }
        ReRandomizationParameters::DerivedCPKWithoutKeySwitch => ((&cks).try_into().unwrap(), None),
    };

    let cpk = CompactPublicKey::new(&cpk_private_key);

    let ksk_rerand_builder = rerand_ksk_params.map(|rerand_ksk_params| {
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params)
    });
    let ksk_rerand = ksk_rerand_builder
        .as_ref()
        .map(|ksk_rerand_builder| ksk_rerand_builder.as_key_switching_key_view());

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(compute_params);
    let noise_simulation_ksk_rerand = rerand_ksk_params.map(|rerand_ksk_params| {
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(
            cpk.parameters(),
            rerand_ksk_params,
            compute_params,
        )
    });
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(compute_params);
    let noise_simulation_bsk =
        NoiseSimulationGenericBootstrapKey::new_from_atomic_pattern_parameters(compute_params);

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(compute_params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    match (noise_simulation_ksk_rerand, ksk_rerand) {
        (Some(noise_simulation_ksk_rerand), Some(ksk_rerand)) => assert!(
            noise_simulation_ksk_rerand.matches_actual_shortint_keyswitching_key(&ksk_rerand)
        ),
        (None, None) => (),
        _ => panic!("Inconsistent br_rerand_dp_ks_ms noise check test setup"),
    }
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));
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
            NoiseSimulationModulus::Other(1 << compute_br_input_modulus_log.0),
        );
        let noise_simulation_input_zero_rerand = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
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
            noise_simulation_ksk_rerand.as_ref(),
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_accumulator,
            compute_br_input_modulus_log,
            &mut (),
        )
    };

    let sample_input = cks.encrypt_noiseless_pbs_input_dyn_lwe(compute_br_input_modulus_log, 0);
    let cpk_zero_sample_input = {
        let compact_list = cpk.encrypt_slice(&[0]);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };
    let id_lut = sks.generate_lookup_table(|x| x);

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash
    // on dimension checks
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
            ksk_rerand.as_ref(),
            max_scalar_mul,
            &sks,
            modulus_switch_config,
            &id_lut,
            compute_br_input_modulus_log,
            &mut (),
        );

        (after_ms.lwe_dimension(), after_ms.raw_modulus_float())
    };

    assert_eq!(after_ms_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = compute_params.message_modulus().0 * compute_params.carry_modulus().0;
    let mut noise_samples_before_ms = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let (
                    (_input, _after_br),
                    (_input_zero_rerand, _after_ksed_zero_rerand),
                    _after_rerand,
                    _after_dp,
                    _after_ks,
                    before_ms,
                    after_ms,
                ) = encrypt_br_rerand_dp_ks_any_ms_noise_helper(
                    compute_params,
                    re_rand_parameters,
                    &cpk_private_key,
                    &cpk,
                    ksk_rerand.as_ref(),
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
        compute_params.lwe_noise_distribution(),
        after_ms_sim.lwe_dimension(),
        after_ms_sim.modulus().as_f64(),
    );

    noise_check(
        &guard,
        mean_variance_result,
        Some(before_ms_normality.null_hypothesis_is_valid),
    );
}

fn noise_check_encrypt_br_rerand_dp_ks_ms_pfail(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    let function_name = this_function_name!();
    let guard = TestJsonGuard::new(&meta_params, filename_suffix, function_name.as_str()).unwrap();
    let (compute_params, re_rand_parameters) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();

        (
            compute_params,
            meta_params
                .rerandomization_parameters()
                .expect("This test requires rerand to be available in parameters"),
        )
    };

    let (pfail_test_meta, compute_params) = {
        let mut ap_params = compute_params;

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

    let cks = ClientKey::new(compute_params);
    let sks = ServerKey::new(&cks);
    let compact_private_key;

    let (cpk_private_key, rerand_ksk_params) = match re_rand_parameters {
        ReRandomizationParameters::LegacyDedicatedCPKWithKeySwitch { rerand_ksk_params } => {
            let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
            let cpk_params = {
                let mut cpk_params = dedicated_cpk_params.pke_params;
                cpk_params.expansion_kind =
                    CompactCiphertextListExpansionKind::NoCasting(compute_params.atomic_pattern());
                cpk_params
            };

            compact_private_key = CompactPrivateKey::new(cpk_params);
            (compact_private_key.as_view(), Some(rerand_ksk_params))
        }
        ReRandomizationParameters::DerivedCPKWithoutKeySwitch => ((&cks).try_into().unwrap(), None),
    };

    let cpk = CompactPublicKey::new(&cpk_private_key);

    let ksk_rerand_builder = rerand_ksk_params.map(|rerand_ksk_params| {
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params)
    });
    let ksk_rerand = ksk_rerand_builder
        .as_ref()
        .map(|ksk_rerand_builder| ksk_rerand_builder.as_key_switching_key_view());

    let max_scalar_mul = sks.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result = encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
                compute_params,
                re_rand_parameters,
                &cpk_private_key,
                &cpk,
                ksk_rerand.as_ref(),
                &cks,
                &sks,
                0,
                max_scalar_mul,
            );
            after_ms_decryption_result.failure_as_f64()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result, &guard);
}

create_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_noise {
    NIST_META_PARAMS_2_2,
});

create_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_pfail {
    NIST_META_PARAMS_2_2,
});
