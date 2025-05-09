use super::{
    scalar_multiplication_variance, should_run_long_pfail_tests, should_use_one_key_per_sample,
};
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::lwe_keyswitch::{
    keyswitch_lwe_ciphertext, keyswitch_lwe_ciphertext_with_scalar_change,
};
use crate::core_crypto::algorithms::lwe_linear_algebra::lwe_ciphertext_plaintext_sub_assign;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128_pbs::programmable_bootstrap_f128_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::algorithms::test::noise_distribution::lwe_encryption_noise::lwe_compact_public_key_encryption_expected_variance;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::noise_formulas::generalized_modulus_switch::generalized_modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::{
    keyswitch_additive_variance_132_bits_security_gaussian,
    keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_packing_keyswitch::{
    packing_keyswitch_additive_variance_132_bits_security_gaussian,
    packing_keyswitch_additive_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::{
    pbs_variance_132_bits_security_gaussian, pbs_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap_128::{
    pbs_128_variance_132_bits_security_gaussian, pbs_128_variance_132_bits_security_tuniform,
};
use crate::core_crypto::commons::noise_formulas::modulus_switch::modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::secure_noise::{
    // minimal_glwe_bound_for_132_bits_security_tuniform,
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform,
};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus as CoreCiphertextModulus, CiphertextModulusLog, DecompositionBaseLog,
    DecompositionLevelCount, GlweDimension, GlweSize, LweCiphertextCount, LweDimension,
    MonomialDegree, NoiseEstimationMeasureBound, PolynomialSize, RSigmaFactor,
};
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, clopper_pearson_exact_confidence_interval, equivalent_pfail_gaussian_noise,
    mean_confidence_interval, normality_test_f64, torus_modular_diff, variance,
    variance_confidence_interval,
};
use crate::core_crypto::commons::traits::{CastFrom, Container, UnsignedInteger};
use crate::core_crypto::entities::{
    Cleartext, GlweSecretKey, LweCiphertext, LweSecretKey, Plaintext,
};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::shortint::atomic_pattern::{AtomicPatternParameters, AtomicPatternServerKey};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{CompressionKey, CompressionPrivateKeys, DecompressionKey};
use crate::shortint::parameters::compact_public_key_only::{
    CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    ShortintCompactCiphertextListCastingMode,
};
use crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters;
use crate::shortint::parameters::list_compression::CompressionParameters;
use crate::shortint::parameters::v1_0::*;
use crate::shortint::parameters::v1_2::V1_2_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DynamicDistribution,
    EncryptionKeyChoice, MessageModulus, ModulusSwitchNoiseReductionParams, ShortintParameterSet,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::{
    apply_modulus_switch_noise_reduction, apply_programmable_bootstrap_no_ms_noise_reduction,
    ModulusSwitchNoiseReductionKey, ShortintBootstrappingKey,
};
use crate::shortint::{
    Ciphertext, ClientKey, CompactPrivateKey, CompactPublicKey, KeySwitchingKey, ServerKey,
};
use rayon::prelude::*;

fn noise_check_shortint_classic_pbs_before_pbs_after_encryption_noise(
    params: ClassicPBSParameters,
) {
    assert!(params.modulus_switch_noise_reduction_params.is_some());
    let params: ShortintParameterSet = params.into();
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let encryption_noise = params.encryption_noise_distribution();

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    // Variance after encryption
    let encryption_variance = match encryption_noise {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let input_ks_lwe_dimension = key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = key_switching_key.decomposition_level_count();

    // Compute expected variance after encryption and the first compute loop until blind rotation,
    // we check the noise before entering the blind rotation
    //
    // For a big key encryption that is:
    // Encrypt -> x MaxNoiseLevel -> KS -> MS (-> BR)

    let scalar_for_multiplication = params.max_noise_level().get();

    let expected_variance_after_multiplication =
        scalar_multiplication_variance(encryption_variance, scalar_for_multiplication);

    // The keyswitching key uses the noise from the lwe_noise_distribution
    let ks_additive_variance = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + ks_additive_variance.0);

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_input_modulus = 1u64 << br_input_modulus_log.0;
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let drift_mitigation_additive_var = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_after_ks.0 + drift_mitigation_additive_var.0);

    let ms_additive_var = generalized_modulus_switch_additive_variance(
        output_ks_lwe_dimension,
        modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples = vec![];

    let sample_count_per_msg = 1000;

    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let mut engine = ShortintEngine::new();
                let thread_cks;
                let thread_sks;
                let (cks, sks) = if should_use_one_key_per_sample() {
                    thread_cks = engine.new_client_key(params);
                    thread_sks = engine.new_server_key(&thread_cks);

                    (&thread_cks, &thread_sks)
                } else {
                    (&cks, &sks)
                };
                let mut ct = cks.unchecked_encrypt(0);
                sks.unchecked_scalar_mul_assign(
                    &mut ct,
                    scalar_for_multiplication.try_into().unwrap(),
                );
                // Put the message back in after mul to have our msg in a noisy ct
                sks.unchecked_scalar_add_assign(&mut ct, msg.try_into().unwrap());

                let mut after_ks_lwe = LweCiphertext::new(
                    0u64,
                    key_switching_key.output_lwe_size(),
                    key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(&key_switching_key, &ct.ct, &mut after_ks_lwe);

                let after_ms = match bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => {
                        let mut after_ms = apply_modulus_switch_noise_reduction(
                            modulus_switch_noise_reduction_key.as_ref().unwrap(),
                            br_input_modulus_log,
                            &after_ks_lwe,
                        );

                        for val in after_ms.as_mut().iter_mut() {
                            *val = modulus_switch(*val, br_input_modulus_log)
                                << shift_to_map_to_native;
                        }

                        after_ms
                    }
                    ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
                };

                let delta = (1u64 << 63) / (cleartext_modulus);
                let expected_plaintext = msg * delta;

                let decrypted = decrypt_lwe_ciphertext(&cks.small_lwe_secret_key(), &after_ms).0;

                // We apply the modulus on the cleartext + the padding bit
                let decoded = round_decode(decrypted, delta) % (2 * cleartext_modulus);
                assert_eq!(decoded, msg);

                torus_modular_diff(expected_plaintext, decrypted, after_ms.ciphertext_modulus())
            })
            .collect();

        noise_samples.extend(current_noise_samples);
    }

    let measured_mean = arithmetic_mean(&noise_samples);
    let measured_variance = variance(&noise_samples);

    let mean_ci = mean_confidence_interval(
        noise_samples.len() as f64,
        measured_mean,
        measured_variance.get_standard_dev(),
        0.99,
    );

    let variance_ci =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    let expected_mean = 0.0;

    println!("measured_variance={measured_variance:?}");
    println!("expected_variance_after_ms={expected_variance_after_ms:?}");
    println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    println!("measured_mean={measured_mean:?}");
    println!("expected_mean={expected_mean:?}");
    println!("mean_lower_bound={:?}", mean_ci.lower_bound());
    println!("mean_upper_bound={:?}", mean_ci.upper_bound());

    // Expected mean is 0
    assert!(mean_ci.mean_is_in_interval(expected_mean));
    // We want to be smaller but secure or in the interval
    if measured_variance <= expected_variance_after_ms {
        let noise_for_security = match params.lwe_noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
        };

        if !variance_ci.variance_is_in_interval(expected_variance_after_ms) {
            println!(
                "\n==========\n\
                Warning: noise formula might be over estimating the noise.\n\
                ==========\n"
            );
        }

        assert!(measured_variance >= noise_for_security);
    } else {
        assert!(variance_ci.variance_is_in_interval(expected_variance_after_ms));
    }

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.01); println!("{}", normality_check.p_value);
    // assert!(normality_check.null_hypothesis_is_valid);
}

create_parameterized_test!(
    noise_check_shortint_classic_pbs_before_pbs_after_encryption_noise {
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    }
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct NoiseSample {
    pub value: f64,
}

#[derive(Clone, Copy, Debug)]
enum DecryptionAndNoiseResult {
    DecryptionSucceeded { noise: NoiseSample },
    DecryptionFailed,
}

impl DecryptionAndNoiseResult {
    fn new<Scalar: UnsignedInteger, CtCont, KeyCont>(
        ct: &LweCiphertext<CtCont>,
        secret_key: &LweSecretKey<KeyCont>,
        expected_msg: Scalar,
        delta: Scalar,
        cleartext_modulus: Scalar,
    ) -> Self
    where
        CtCont: Container<Element = Scalar>,
        KeyCont: Container<Element = Scalar>,
    {
        let decrypted_plaintext = decrypt_lwe_ciphertext(secret_key, ct).0;

        // We apply the modulus on the cleartext + the padding bit
        let decoded_msg =
            round_decode(decrypted_plaintext, delta) % (Scalar::TWO * cleartext_modulus);

        let expected_plaintext = expected_msg * delta;

        let noise = torus_modular_diff(
            expected_plaintext,
            decrypted_plaintext,
            ct.ciphertext_modulus(),
        );

        if decoded_msg == expected_msg {
            Self::DecryptionSucceeded {
                noise: NoiseSample { value: noise },
            }
        } else {
            Self::DecryptionFailed
        }
    }
}

fn new_noiseless_modswitched_lwe<Scalar: UnsignedInteger + CastFrom<u64>>(
    cks: &ClientKey,
    br_input_modulus_log: CiphertextModulusLog,
    cleartext_modulus: u64,
    msg: u64,
    engine: &mut ShortintEngine,
    ciphertext_modulus: CoreCiphertextModulus<Scalar>,
) -> LweCiphertext<Vec<Scalar>> {
    let ms_modulus = CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
    let no_noise_dist = DynamicDistribution::new_gaussian(Variance(0.0));

    let ms_delta = ms_modulus.get_custom_modulus() as u64 / (2 * cleartext_modulus);

    let ms_plaintext = Plaintext(msg * ms_delta);

    let simulated_mod_switch_ct = allocate_and_encrypt_new_lwe_ciphertext(
        &cks.small_lwe_secret_key(),
        ms_plaintext,
        no_noise_dist,
        ms_modulus,
        &mut engine.encryption_generator,
    );

    let raw_data = simulated_mod_switch_ct.into_container();

    assert!(Scalar::BITS <= u64::BITS as usize);

    let raw_data_as_scalar: Vec<Scalar> = raw_data
        .into_iter()
        .map(|x| Scalar::cast_from(x >> (u64::BITS as usize - Scalar::BITS as usize)))
        .collect();

    // Now get the noiseless mod switched encryption under the proper modulus
    // The power of 2 modulus are always encrypted in the MSBs, so this is fine
    LweCiphertext::from_container(raw_data_as_scalar, ciphertext_modulus)
}

fn convert_dyn_lwe_for_decryption(dyn_lwe: DynLwe) -> LweCiphertext<Vec<u64>> {
    match dyn_lwe {
        DynLwe::U32(lwe_ciphertext) => {
            let tmp: Vec<u64> = lwe_ciphertext
                .into_container()
                .into_iter()
                .map(|x| (x as u64) << 32)
                .collect();
            // Valid as power of 2 stuff is in the MSBs anyways
            LweCiphertext::from_container(tmp, CiphertextModulus::new_native())
        }
        DynLwe::U64(lwe_ciphertext) => lwe_ciphertext,
    }
}

fn classic_pbs_atomic_pattern_inner_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let params_ap = params.ap_parameters().unwrap();
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let mut engine = ShortintEngine::new();
    let thread_cks;
    let thread_sks;
    let (cks, sks) = if should_use_one_key_per_sample() {
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        (&thread_cks, &thread_sks)
    } else {
        // If we don't want to use per thread keys (to go faster), we use those single keys for all
        // threads
        (single_cks, single_sks)
    };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    let delta = (1u64 << 63) / cleartext_modulus;
    let native_mod_plaintext = Plaintext(msg * delta);

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            DynKsk::U64(
                standard_atomic_pattern_server_key
                    .key_switching_key
                    .as_view(),
            ),
            DynBsk::U64(&standard_atomic_pattern_server_key.bootstrapping_key),
        ),
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => (
            DynKsk::U32(ks32_atomic_pattern_server_key.key_switching_key.as_view()),
            DynBsk::U32(&ks32_atomic_pattern_server_key.bootstrapping_key),
        ),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let input_pbs_lwe_ct = match (key_switching_key, bootstrapping_key) {
        (DynKsk::U32(_lwe_keyswitch_key), DynBsk::U32(_shortint_bootstrapping_key)) => {
            let modulus = match params_ap {
                AtomicPatternParameters::Standard(_pbsparameters) => unreachable!(),
                AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                    key_switch32_pbsparameters.post_keyswitch_ciphertext_modulus
                }
            };
            DynLwe::U32(new_noiseless_modswitched_lwe(
                cks,
                br_input_modulus_log,
                cleartext_modulus,
                msg,
                &mut engine,
                modulus,
            ))
        }
        (DynKsk::U64(_lwe_keyswitch_key), DynBsk::U64(_shortint_bootstrapping_key)) => {
            assert!(params.pbs_only());
            DynLwe::U64(new_noiseless_modswitched_lwe(
                cks,
                br_input_modulus_log,
                cleartext_modulus,
                msg,
                &mut engine,
                params.ciphertext_modulus(),
            ))
        }
        _ => unreachable!(),
    };

    let mut after_pbs_shortint_ct = sks.unchecked_create_trivial_with_lwe_size(
        Cleartext(0),
        bootstrapping_key.output_lwe_dimension().to_lwe_size(),
    );

    let buffers = engine.get_computation_buffers();

    match (bootstrapping_key, input_pbs_lwe_ct) {
        (DynBsk::U32(shortint_bootstrapping_key), DynLwe::U32(input_pbs_lwe_ct)) => {
            // Apply the PBS only and no noise reduction as we have a noiseless input ciphertext
            apply_programmable_bootstrap_no_ms_noise_reduction(
                shortint_bootstrapping_key,
                &input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.ct,
                &identity_lut.acc,
                buffers,
            );
        }
        (DynBsk::U64(shortint_bootstrapping_key), DynLwe::U64(input_pbs_lwe_ct)) => {
            apply_programmable_bootstrap_no_ms_noise_reduction(
                shortint_bootstrapping_key,
                &input_pbs_lwe_ct,
                &mut after_pbs_shortint_ct.ct,
                &identity_lut.acc,
                buffers,
            );
        }
        _ => unreachable!(),
    }

    after_pbs_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    // Remove the plaintext before the mul to avoid degree issues but sill increase the
    // noise
    lwe_ciphertext_plaintext_sub_assign(&mut after_pbs_shortint_ct.ct, native_mod_plaintext);

    sks.unchecked_scalar_mul_assign(&mut after_pbs_shortint_ct, scalar_for_multiplication);

    // Put the message back in after mul to have our msg in a noisy ct
    sks.unchecked_scalar_add_assign(&mut after_pbs_shortint_ct, msg.try_into().unwrap());

    let after_ks_lwe = match key_switching_key {
        DynKsk::U32(lwe_keyswitch_key) => {
            let mut tmp = LweCiphertext::new(
                0,
                lwe_keyswitch_key.output_lwe_size(),
                lwe_keyswitch_key.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext_with_scalar_change(
                &lwe_keyswitch_key,
                &after_pbs_shortint_ct.ct,
                &mut tmp,
            );
            DynLwe::U32(tmp)
        }
        DynKsk::U64(lwe_keyswitch_key) => {
            let mut tmp = LweCiphertext::new(
                0,
                lwe_keyswitch_key.output_lwe_size(),
                lwe_keyswitch_key.ciphertext_modulus(),
            );
            keyswitch_lwe_ciphertext(&lwe_keyswitch_key, &after_pbs_shortint_ct.ct, &mut tmp);
            DynLwe::U64(tmp)
        }
    };

    let (after_drift_mitigation, after_ms) = match (bootstrapping_key, &after_ks_lwe) {
        (DynBsk::U32(bootstrapping_key), DynLwe::U32(after_ks_lwe)) => match bootstrapping_key {
            ShortintBootstrappingKey::Classic {
                bsk: _,
                modulus_switch_noise_reduction_key,
            } => {
                let mut after_ms = apply_modulus_switch_noise_reduction(
                    modulus_switch_noise_reduction_key.as_ref().unwrap(),
                    br_input_modulus_log,
                    &after_ks_lwe,
                );
                let after_drift_mitigation = after_ms.clone();
                let shift_to_map_to_native = u32::BITS - br_input_modulus_log.0 as u32;
                for val in after_ms.as_mut().iter_mut() {
                    *val = modulus_switch(*val, br_input_modulus_log) << shift_to_map_to_native;
                }

                (DynLwe::U32(after_drift_mitigation), DynLwe::U32(after_ms))
            }
            ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
        },
        (DynBsk::U64(bootstrapping_key), DynLwe::U64(after_ks_lwe)) => match bootstrapping_key {
            ShortintBootstrappingKey::Classic {
                bsk: _,
                modulus_switch_noise_reduction_key,
            } => {
                let mut after_ms = apply_modulus_switch_noise_reduction(
                    modulus_switch_noise_reduction_key.as_ref().unwrap(),
                    br_input_modulus_log,
                    &after_ks_lwe,
                );
                let after_drift_mitigation = after_ms.clone();
                let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;
                for val in after_ms.as_mut().iter_mut() {
                    *val = modulus_switch(*val, br_input_modulus_log) << shift_to_map_to_native;
                }

                (DynLwe::U64(after_drift_mitigation), DynLwe::U64(after_ms))
            }
            ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
        },
        _ => unreachable!(),
    };

    let (after_ks_lwe, after_drift_mitigation, after_ms) = (
        convert_dyn_lwe_for_decryption(after_ks_lwe),
        convert_dyn_lwe_for_decryption(after_drift_mitigation),
        convert_dyn_lwe_for_decryption(after_ms),
    );

    (
        DecryptionAndNoiseResult::new(
            &after_ks_lwe,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &after_drift_mitigation,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &after_ms,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
    )
}

fn classic_pbs_atomic_pattern_noise_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> ((NoiseSample, NoiseSample), NoiseSample) {
    let (
        decryption_and_noise_result_after_ks,
        decryption_and_noise_result_after_drift_mitigation,
        decryption_and_noise_result_after_ms,
    ) = classic_pbs_atomic_pattern_inner_helper(
        params,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    (
        (
            match decryption_and_noise_result_after_ks {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
            match decryption_and_noise_result_after_drift_mitigation {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
        ),
        match decryption_and_noise_result_after_ms {
            DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
            DecryptionAndNoiseResult::DecryptionFailed => {
                panic!("Failed decryption, noise measurement will be wrong.")
            }
        },
    )
}

/// Return 1 if the decryption failed, otherwise 0, allowing to sum the results of threads to get
/// the failure rate.
fn classic_pbs_atomic_pattern_pfail_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> f64 {
    let (
        _decryption_and_noise_result_after_ks,
        _decrypteion_and_noise_result_after_drift_mitigation,
        decryption_and_noise_result_after_ms,
    ) = classic_pbs_atomic_pattern_inner_helper(
        params,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    match decryption_and_noise_result_after_ms {
        DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
        DecryptionAndNoiseResult::DecryptionFailed => 1.0,
    }
}

enum DynLwe {
    U32(LweCiphertext<Vec<u32>>),
    U64(LweCiphertext<Vec<u64>>),
}

#[derive(Clone, Copy)]
enum DynKsk<'key> {
    U32(crate::core_crypto::entities::LweKeyswitchKey<&'key [u32]>),
    U64(crate::core_crypto::entities::LweKeyswitchKey<&'key [u64]>),
}

impl DynKsk<'_> {
    fn input_key_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::U32(inner) => inner.input_key_lwe_dimension(),
            Self::U64(inner) => inner.input_key_lwe_dimension(),
        }
    }

    fn output_key_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::U32(inner) => inner.output_key_lwe_dimension(),
            Self::U64(inner) => inner.output_key_lwe_dimension(),
        }
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::U32(inner) => inner.decomposition_base_log(),
            Self::U64(inner) => inner.decomposition_base_log(),
        }
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::U32(inner) => inner.decomposition_level_count(),
            Self::U64(inner) => inner.decomposition_level_count(),
        }
    }
}

#[derive(Clone, Copy)]
enum DynBsk<'key> {
    U32(&'key ShortintBootstrappingKey<u32>),
    U64(&'key ShortintBootstrappingKey<u64>),
}

impl DynBsk<'_> {
    fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::U32(inner) => inner.input_lwe_dimension(),
            Self::U64(inner) => inner.input_lwe_dimension(),
        }
    }
    fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::U32(inner) => inner.output_lwe_dimension(),
            Self::U64(inner) => inner.output_lwe_dimension(),
        }
    }
    fn glwe_size(&self) -> GlweSize {
        match self {
            Self::U32(inner) => inner.glwe_size(),
            Self::U64(inner) => inner.glwe_size(),
        }
    }
    fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::U32(inner) => inner.polynomial_size(),
            Self::U64(inner) => inner.polynomial_size(),
        }
    }
    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::U32(inner) => inner.decomposition_base_log(),
            Self::U64(inner) => inner.decomposition_base_log(),
        }
    }
    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::U32(inner) => inner.decomposition_level_count(),
            Self::U64(inner) => inner.decomposition_level_count(),
        }
    }
}

fn noise_check_shortint_classic_pbs_atomic_pattern_noise<P: Into<AtomicPatternParameters>>(
    params: P,
) {
    let params_ap: AtomicPatternParameters = params.into();
    match params_ap {
        AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
            crate::shortint::PBSParameters::PBS(classic_pbsparameters) => {
                assert!(classic_pbsparameters
                    .modulus_switch_noise_reduction_params
                    .is_some())
            }
            crate::shortint::PBSParameters::MultiBitPBS(_multi_bit_pbsparameters) => (),
        },
        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
            assert!(key_switch32_pbsparameters
                .modulus_switch_noise_reduction_params
                .is_some())
        }
    };

    let params: ShortintParameterSet = params_ap.into();
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let (ks_modulus_as_f64, modulus_as_f64) = match params_ap {
        AtomicPatternParameters::Standard(pbsparameters) => {
            if pbsparameters.ciphertext_modulus().is_native_modulus() {
                (2.0f64.powi(64), 2.0f64.powi(64))
            } else {
                (
                    pbsparameters.ciphertext_modulus().get_custom_modulus() as f64,
                    pbsparameters.ciphertext_modulus().get_custom_modulus() as f64,
                )
            }
        }
        AtomicPatternParameters::KeySwitch32(ks32_pbsparameters) => {
            let ks_modulus = if ks32_pbsparameters
                .post_keyswitch_ciphertext_modulus
                .is_native_modulus()
            {
                2.0f64.powi(32)
            } else {
                ks32_pbsparameters
                    .post_keyswitch_ciphertext_modulus
                    .get_custom_modulus() as f64
            };
            let pbs_modulus = if ks32_pbsparameters.ciphertext_modulus.is_native_modulus() {
                2.0f64.powi(64)
            } else {
                ks32_pbsparameters.ciphertext_modulus.get_custom_modulus() as f64
            };
            (ks_modulus, pbs_modulus)
        }
    };

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            DynKsk::U64(
                standard_atomic_pattern_server_key
                    .key_switching_key
                    .as_view(),
            ),
            DynBsk::U64(&standard_atomic_pattern_server_key.bootstrapping_key),
        ),
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => (
            DynKsk::U32(ks32_atomic_pattern_server_key.key_switching_key.as_view()),
            DynBsk::U32(&ks32_atomic_pattern_server_key.bootstrapping_key),
        ),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let input_pbs_lwe_dimension = bootstrapping_key.input_lwe_dimension();
    let output_glwe_dimension = bootstrapping_key.glwe_size().to_glwe_dimension();
    let output_polynomial_size = bootstrapping_key.polynomial_size();
    let pbs_decomp_base_log = bootstrapping_key.decomposition_base_log();
    let pbs_decomp_level_count = bootstrapping_key.decomposition_level_count();

    let input_ks_lwe_dimension = key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = key_switching_key.decomposition_level_count();

    // Compute expected variance after getting out of a PBS and doing a full AP until the next mod
    // switch
    //
    // For a big key encryption that is:
    // Encrypt under modulus 2N (start at modswitch) -> BR -> SE -> x MaxNoiseLevel -> KS -> MS (->
    // BR)

    let scalar_for_multiplication = params.max_noise_level().get();

    let expected_variance_after_pbs = match params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            input_pbs_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            pbs_decomp_base_log,
            pbs_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            input_pbs_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            pbs_decomp_base_log,
            pbs_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_multiplication =
        scalar_multiplication_variance(expected_variance_after_pbs, scalar_for_multiplication);

    // The keyswitching key uses the noise from the lwe_noise_distribution
    let ks_additive_variance = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            ks_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            input_ks_lwe_dimension,
            output_ks_lwe_dimension,
            ks_decomp_base_log,
            ks_decomp_level_count,
            ks_modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + ks_additive_variance.0);

    let br_input_modulus_log = params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_input_modulus = 1u64 << br_input_modulus_log.0;

    let drift_mitigation_additive_var = match params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(ks_modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_after_ks.0 + drift_mitigation_additive_var.0);

    let ms_additive_var = generalized_modulus_switch_additive_variance(
        output_ks_lwe_dimension,
        ks_modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_ks = vec![];
    let mut noise_samples_after_drift_mitigation = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000;

    for msg in 0..cleartext_modulus {
        let (
            (current_noise_samples_after_ks, current_noise_samples_after_drift_mitigation),
            current_noise_samples_after_ms,
        ): ((Vec<_>, Vec<_>), Vec<_>) = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                classic_pbs_atomic_pattern_noise_helper(
                    params,
                    &cks,
                    &sks,
                    msg,
                    scalar_for_multiplication.try_into().unwrap(),
                )
            })
            .unzip();

        noise_samples_after_ks.extend(current_noise_samples_after_ks.into_iter().map(|x| x.value));
        noise_samples_after_drift_mitigation.extend(
            current_noise_samples_after_drift_mitigation
                .into_iter()
                .map(|x| x.value),
        );
        noise_samples_after_ms.extend(current_noise_samples_after_ms.into_iter().map(|x| x.value));
    }

    // let measured_mean_after_ms = arithmetic_mean(&noise_samples_after_ms);
    // let measured_variance_after_ms = variance(&noise_samples_after_ms);

    // let mean_ci = mean_confidence_interval(
    //     noise_samples_after_ms.len() as f64,
    //     measured_mean_after_ms,
    //     measured_variance_after_ms.get_standard_dev(),
    //     0.99,
    // );

    // let variance_ci = variance_confidence_interval(
    //     noise_samples_after_ms.len() as f64,
    //     measured_variance_after_ms,
    //     0.99,
    // );

    // let expected_mean_after_ms = 0.0;

    // println!("measured_variance_after_ms={measured_variance_after_ms:?}");
    // println!("expected_variance_after_ms={expected_variance_after_ms:?}");
    // println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    // println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    // println!("measured_mean_after_ms={measured_mean_after_ms:?}");
    // println!("expected_mean_after_ms={expected_mean_after_ms:?}");
    // println!("mean_lower_bound={:?}", mean_ci.lower_bound());
    // println!("mean_upper_bound={:?}", mean_ci.upper_bound());

    // // Expected mean is 0
    // assert!(mean_ci.mean_is_in_interval(expected_mean_after_ms));
    // // We want to be smaller but secure or in the interval
    // if measured_variance_after_ms <= expected_variance_after_ms {
    //     let noise_for_security = match params.lwe_noise_distribution() {
    //         DynamicDistribution::Gaussian(_) => {
    //             minimal_lwe_variance_for_132_bits_security_gaussian(
    //                 sks.bootstrapping_key.input_lwe_dimension(),
    //                 modulus_as_f64,
    //             )
    //         }
    //         DynamicDistribution::TUniform(_) => {
    //             minimal_lwe_variance_for_132_bits_security_tuniform(
    //                 sks.bootstrapping_key.input_lwe_dimension(),
    //                 modulus_as_f64,
    //             )
    //         }
    //     };

    //     if !variance_ci.variance_is_in_interval(expected_variance_after_ms) {
    //         println!(
    //             "\n==========\n\
    //             Warning: noise formula might be over estimating the noise.\n\
    //             ==========\n"
    //         );
    //     }

    //     assert!(measured_variance_after_ms >= noise_for_security);
    // } else {
    //     assert!(variance_ci.variance_is_in_interval(expected_variance_after_ms));
    // }

    let after_ks_ok = mean_and_variance_check(
        &noise_samples_after_ks,
        "after_ks",
        0.0,
        expected_variance_after_ks,
        params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        modulus_as_f64,
    );

    let after_drift_mitigation_ok = mean_and_variance_check(
        &noise_samples_after_drift_mitigation,
        "after_drift_mitigation",
        0.0,
        expected_variance_after_drift_mitigation,
        params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        modulus_as_f64,
    );

    let after_ms_ok = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        0.0,
        expected_variance_after_ms,
        params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        modulus_as_f64,
    );

    let ks_normality_check = normality_test_f64(
        &noise_samples_after_ks[..5000.min(noise_samples_after_ks.len())],
        0.01,
    );

    if ks_normality_check.null_hypothesis_is_valid {
        println!("Normality check after KS is OK\n");
    } else {
        println!("Normality check after KS failed\n");
    }

    let drift_mitigation_normality_check = normality_test_f64(
        &noise_samples_after_drift_mitigation
            [..5000.min(noise_samples_after_drift_mitigation.len())],
        0.01,
    );

    if drift_mitigation_normality_check.null_hypothesis_is_valid {
        println!("Normality check after drift mitigation is OK\n");
    } else {
        println!("Normality check after drift mitigation failed\n");
    }

    assert!(
        after_ks_ok
            && after_drift_mitigation_ok
            && after_ms_ok
            && ks_normality_check.null_hypothesis_is_valid
            && drift_mitigation_normality_check.null_hypothesis_is_valid
    );

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_noise {
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_2_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128
});

fn noise_check_shortint_classic_pbs_atomic_pattern_pfail<P: Into<AtomicPatternParameters>>(
    params: P,
) {
    let mut params: AtomicPatternParameters = params.into();

    let log2_p_fail = match params {
        AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
            crate::shortint::PBSParameters::PBS(classic_pbsparameters) => {
                assert!(classic_pbsparameters
                    .modulus_switch_noise_reduction_params
                    .is_some());
                classic_pbsparameters.log2_p_fail
            }
            crate::shortint::PBSParameters::MultiBitPBS(multi_bit_pbsparameters) => {
                multi_bit_pbsparameters.log2_p_fail
            }
        },
        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
            assert!(key_switch32_pbsparameters
                .modulus_switch_noise_reduction_params
                .is_some());
            key_switch32_pbsparameters.log2_p_fail
        }
    };

    assert_eq!(
        params.carry_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        params.message_modulus().0,
        4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * params.carry_modulus().0 * params.message_modulus().0).ilog2();

    match &mut params {
        AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
            crate::shortint::PBSParameters::PBS(classic_pbsparameters) => {
                (*classic_pbsparameters).carry_modulus.0 = 1 << 4
            }
            crate::shortint::PBSParameters::MultiBitPBS(multi_bit_pbsparameters) => {
                (*multi_bit_pbsparameters).carry_modulus.0 = 1 << 4
            }
        },
        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
            (*key_switch32_pbsparameters).carry_modulus.0 = 1 << 4
        }
    }

    let new_precision_with_padding =
        (2 * params.carry_modulus().0 * params.message_modulus().0).ilog2();

    let original_pfail = 2.0f64.powf(log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", log2_p_fail);

    let expected_pfail = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_log2 = expected_pfail.log2();

    println!("expected_pfail={expected_pfail}");
    println!("expected_pfail_log2={}", expected_pfail_log2);

    let (runs_for_expected_fails, expected_fails) = if should_run_long_pfail_tests() {
        let total_runs = 1_000_000;
        let expected_fails = (total_runs as f64 * expected_pfail).round() as u32;
        (total_runs, expected_fails)
    } else {
        let expected_fails = 200;
        let runs_for_expected_fails = (expected_fails as f64 / expected_pfail).round() as u32;
        (runs_for_expected_fails, expected_fails)
    };

    println!("runs_for_expected_fails={runs_for_expected_fails}");

    let params: ShortintParameterSet = params.into();
    assert!(
        matches!(params.encryption_key_choice(), EncryptionKeyChoice::Big),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let scalar_for_multiplication = params.max_noise_level().get();

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let measured_fails: f64 = (0..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;

            classic_pbs_atomic_pattern_pfail_helper(
                params,
                &cks,
                &sks,
                msg,
                scalar_for_multiplication.try_into().unwrap(),
            )
        })
        .sum();

    let measured_pfail = measured_fails / (runs_for_expected_fails as f64);

    println!("measured_fails={measured_fails}");
    println!("expected_fails={expected_fails}");
    println!("measured_pfail={measured_pfail}");
    println!("expected_pfail={expected_pfail}");

    let equivalent_measured_pfail = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail={equivalent_measured_pfail}");
    println!("original_expected_pfail  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_log2={}",
        equivalent_measured_pfail.log2()
    );
    println!("original_expected_pfail_log2  ={}", original_pfail.log2());

    if measured_fails > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail <= expected_pfail {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters, \
            or some hypothesis does not hold.\n\
            ==========\n"
        );
    }
}

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_pfail {
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_2_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128
});

#[allow(clippy::too_many_arguments)]
fn pke_encrypt_ks_to_compute_inner_helper(
    cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    block_params: ShortintParameterSet,
    single_cpk: &CompactPublicKey,
    single_ksk: &KeySwitchingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let mut engine = ShortintEngine::new();
    let thread_compact_encryption_secret_key;
    let thread_cpk;
    let thread_ksk;
    let thread_cks;
    let thread_sks;
    let (cpk, ksk, cks, sks) = if should_use_one_key_per_sample() {
        thread_compact_encryption_secret_key = CompactPrivateKey::new(cpke_params);
        thread_cpk = CompactPublicKey::new(&thread_compact_encryption_secret_key);
        thread_cks = engine.new_client_key(block_params);
        thread_sks = engine.new_server_key(&thread_cks);
        thread_ksk = KeySwitchingKey::new(
            (&thread_compact_encryption_secret_key, None),
            (&thread_cks, &thread_sks),
            ksk_params,
        );

        (&thread_cpk, &thread_ksk, &thread_cks, &thread_sks)
    } else {
        // If we don't want to use per thread keys (to go faster), we use those single keys for all
        // threads
        (single_cpk, single_ksk, single_cks, single_sks)
    };

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let br_input_modulus_log = block_params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;

    let shortint_compact_ct_list = cpk.encrypt_slice_with_modulus(&[msg], cleartext_modulus);
    let expanded = shortint_compact_ct_list
        .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
        .unwrap();
    let expanded_ct = expanded.into_iter().next().unwrap();

    let core_ksk = &ksk.key_switching_key_material.key_switching_key;

    let mut after_ks_lwe_ct = LweCiphertext::new(
        0u64,
        core_ksk.output_lwe_size(),
        core_ksk.ciphertext_modulus(),
    );

    // We don't call the ksk.cast function from shortint as it's doing too many automatic things
    keyswitch_lwe_ciphertext(core_ksk, &expanded_ct.ct, &mut after_ks_lwe_ct);

    let before_ms = {
        match ksk_params.destination_key {
            EncryptionKeyChoice::Big => {
                let mut shortint_ct_after_pke_ks = Ciphertext::new(
                    after_ks_lwe_ct,
                    expanded_ct.degree,
                    expanded_ct.noise_level(),
                    expanded_ct.message_modulus,
                    expanded_ct.carry_modulus,
                    expanded_ct.atomic_pattern,
                );

                // First remove the msg from the ciphertext to avoid a problem with the mul result
                // overflowing
                lwe_ciphertext_plaintext_sub_assign(
                    &mut shortint_ct_after_pke_ks.ct,
                    Plaintext(delta * msg),
                );

                sks.unchecked_scalar_mul_assign(
                    &mut shortint_ct_after_pke_ks,
                    scalar_for_multiplication.try_into().unwrap(),
                );

                // Put it back in
                sks.unchecked_scalar_add_assign(
                    &mut shortint_ct_after_pke_ks,
                    msg.try_into().unwrap(),
                );

                let mut lwe_keyswitchted = LweCiphertext::new(
                    0u64,
                    key_switching_key.output_lwe_size(),
                    key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(
                    &key_switching_key,
                    &shortint_ct_after_pke_ks.ct,
                    &mut lwe_keyswitchted,
                );

                // Return the result
                lwe_keyswitchted
            }
            EncryptionKeyChoice::Small => after_ks_lwe_ct,
        }
    };

    let after_ms = match bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk: _,
            modulus_switch_noise_reduction_key,
        } => {
            let mut after_ms = apply_modulus_switch_noise_reduction(
                modulus_switch_noise_reduction_key.as_ref().unwrap(),
                br_input_modulus_log,
                &before_ms,
            );

            for val in after_ms.as_mut().iter_mut() {
                *val = modulus_switch(*val, br_input_modulus_log) << shift_to_map_to_native;
            }

            after_ms
        }
        ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
    };

    DecryptionAndNoiseResult::new(
        &after_ms,
        &cks.small_lwe_secret_key(),
        msg,
        delta,
        cleartext_modulus,
    )
}

#[allow(clippy::too_many_arguments)]
fn pke_encrypt_ks_to_compute_noise_helper(
    cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    block_params: ShortintParameterSet,
    single_cpk: &CompactPublicKey,
    single_ksk: &KeySwitchingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> NoiseSample {
    let decryption_and_noise_result = pke_encrypt_ks_to_compute_inner_helper(
        cpke_params,
        ksk_params,
        block_params,
        single_cpk,
        single_ksk,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    match decryption_and_noise_result {
        DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
        DecryptionAndNoiseResult::DecryptionFailed => {
            panic!("Failed decryption, noise measurement will be wrong.")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pke_encrypt_ks_to_compute_pfail_helper(
    cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    block_params: ShortintParameterSet,
    single_cpk: &CompactPublicKey,
    single_ksk: &KeySwitchingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> f64 {
    let decryption_and_noise_result = pke_encrypt_ks_to_compute_inner_helper(
        cpke_params,
        ksk_params,
        block_params,
        single_cpk,
        single_ksk,
        single_cks,
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    match decryption_and_noise_result {
        DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
        DecryptionAndNoiseResult::DecryptionFailed => 1.0,
    }
}

fn noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
    mut cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    block_params: ClassicPBSParameters,
) {
    // Disable the auto casting in the keyswitching key to be able to measure things ourselves
    cpke_params.expansion_kind =
        CompactCiphertextListExpansionKind::NoCasting(block_params.encryption_key_choice.into());
    // Remove mutability
    let cpke_params = cpke_params;

    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let compact_encryption_secret_key = CompactPrivateKey::new(cpke_params);
    let cpk = CompactPublicKey::new(&compact_encryption_secret_key);

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);

    let ksk = KeySwitchingKey::new(
        (&compact_encryption_secret_key, None),
        (&cks, &sks),
        ksk_params,
    );

    let cpk_lwe_dimension = cpk.parameters.encryption_lwe_dimension;
    let cpk_encryption_noise = cpk.parameters.encryption_noise_distribution;

    let encryption_variance = match cpk_encryption_noise {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let pke_ks_input_lwe_dimension = ksk
        .key_switching_key_material
        .key_switching_key
        .input_key_lwe_dimension();
    let pke_ks_output_lwe_dimension = ksk
        .key_switching_key_material
        .key_switching_key
        .output_key_lwe_dimension();
    let pke_ks_decomp_base_log = ksk
        .key_switching_key_material
        .key_switching_key
        .decomposition_base_log();
    let pke_ks_decomp_level_count = ksk
        .key_switching_key_material
        .key_switching_key
        .decomposition_level_count();

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let compute_ks_input_lwe_dimension = key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = key_switching_key.decomposition_level_count();

    let compute_pbs_input_lwe_dimension = bootstrapping_key.input_lwe_dimension();

    // Only in the Big key case
    let scalar_for_multiplication = block_params.max_noise_level().get();

    // Compute expected variance after getting out of the PKE and doing the keyswitch to the compute
    // parameters until the first blind rotation mod switch.
    //
    // This gives:
    // For a KS to the small destination key:
    // Encrypt PKE -> PKE-KS -> MS
    //
    // For a KS to the big destination key:
    // Encrypt PKE -> PKE-KS -> times MaxNoiseLevel -> KS -> MS

    let expected_variance_after_cpke =
        lwe_compact_public_key_encryption_expected_variance(encryption_variance, cpk_lwe_dimension);

    // The encryption noise for the keyswitching keys comes from the destination params as we are
    // keyswitching to a dimension of the parameter set.
    let pke_ks_additive_variance = {
        let destination_encryption_noise_distribution = match ksk_params.destination_key {
            EncryptionKeyChoice::Big => block_params.glwe_noise_distribution(),
            EncryptionKeyChoice::Small => block_params.lwe_noise_distribution(),
        };

        match destination_encryption_noise_distribution {
            DynamicDistribution::Gaussian(_) => {
                keyswitch_additive_variance_132_bits_security_gaussian(
                    pke_ks_input_lwe_dimension,
                    pke_ks_output_lwe_dimension,
                    pke_ks_decomp_base_log,
                    pke_ks_decomp_level_count,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                keyswitch_additive_variance_132_bits_security_tuniform(
                    pke_ks_input_lwe_dimension,
                    pke_ks_output_lwe_dimension,
                    pke_ks_decomp_base_log,
                    pke_ks_decomp_level_count,
                    modulus_as_f64,
                )
            }
        }
    };

    let expected_variance_after_pke_ks =
        Variance(expected_variance_after_cpke.0 + pke_ks_additive_variance.0);

    let expected_variance_before_drift_mitigation = {
        match ksk_params.destination_key {
            // In the case of the Big key we are allowed theoretically to do the AP
            EncryptionKeyChoice::Big => {
                let expected_variance_after_scalar_mul = scalar_multiplication_variance(
                    expected_variance_after_pke_ks,
                    scalar_for_multiplication,
                );

                let compute_ks_additive_variance = match block_params.lwe_noise_distribution() {
                    DynamicDistribution::Gaussian(_) => {
                        keyswitch_additive_variance_132_bits_security_gaussian(
                            compute_ks_input_lwe_dimension,
                            compute_ks_output_lwe_dimension,
                            compute_ks_decomp_base_log,
                            compute_ks_decomp_level_count,
                            modulus_as_f64,
                        )
                    }
                    DynamicDistribution::TUniform(_) => {
                        keyswitch_additive_variance_132_bits_security_tuniform(
                            compute_ks_input_lwe_dimension,
                            compute_ks_output_lwe_dimension,
                            compute_ks_decomp_base_log,
                            compute_ks_decomp_level_count,
                            modulus_as_f64,
                        )
                    }
                };

                Variance(expected_variance_after_scalar_mul.0 + compute_ks_additive_variance.0)
            }
            EncryptionKeyChoice::Small => expected_variance_after_pke_ks,
        }
    };

    let br_input_modulus_log = block_params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_input_modulus = 1u64 << br_input_modulus_log.0;

    // TODO output noise after drift mitigation, check normality
    let drift_mitigation_additive_var = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_before_drift_mitigation.0 + drift_mitigation_additive_var.0);

    let ms_additive_variance = generalized_modulus_switch_additive_variance(
        compute_pbs_input_lwe_dimension,
        modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ms_additive_variance.0);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples = vec![];

    let sample_count_per_msg = 1000;

    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                pke_encrypt_ks_to_compute_noise_helper(
                    cpke_params,
                    ksk_params,
                    block_params,
                    &cpk,
                    &ksk,
                    &cks,
                    &sks,
                    msg,
                    scalar_for_multiplication,
                )
                .value
            })
            .collect();

        noise_samples.extend(current_noise_samples);
    }

    let measured_mean = arithmetic_mean(&noise_samples);
    let measured_variance = variance(&noise_samples);

    let mean_ci = mean_confidence_interval(
        noise_samples.len() as f64,
        measured_mean,
        measured_variance.get_standard_dev(),
        0.99,
    );

    let variance_ci =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    let expected_mean = 0.0;

    println!("measured_variance={measured_variance:?}");
    println!("expected_variance_after_ms={expected_variance_after_ms:?}");
    println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    println!("measured_mean={measured_mean:?}");
    println!("expected_mean={expected_mean:?}");
    println!("mean_lower_bound={:?}", mean_ci.lower_bound());
    println!("mean_upper_bound={:?}", mean_ci.upper_bound());

    // Expected mean is 0
    assert!(mean_ci.mean_is_in_interval(expected_mean));
    // We want to be smaller but secure or in the interval
    if measured_variance <= expected_variance_after_ms {
        let noise_for_security = match block_params.lwe_noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
        };

        if !variance_ci.variance_is_in_interval(expected_variance_after_ms) {
            println!(
                "\n==========\n\
                Warning: noise formula might be over estimating the noise.\n\
                ==========\n"
            );
        }

        assert!(measured_variance >= noise_for_security);
    } else {
        assert!(variance_ci.variance_is_in_interval(expected_variance_after_ms));
    }

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_small_noise() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_small_noise_zkv1() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
        V1_0_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_noise() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_noise_zkv1() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
        V1_0_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
    mut cpke_params: CompactPublicKeyEncryptionParameters,
    ksk_params: ShortintKeySwitchingParameters,
    mut block_params: ClassicPBSParameters,
) {
    assert_eq!(
        block_params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus.0 * block_params.message_modulus.0).ilog2();
    block_params.carry_modulus.0 = 1 << 4;
    cpke_params.carry_modulus = block_params.carry_modulus;

    let new_precision_with_padding =
        (2 * block_params.carry_modulus.0 * block_params.message_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail);

    let expected_pfail = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    block_params.log2_p_fail = expected_pfail.log2();

    println!("expected_pfail={expected_pfail}");
    println!("expected_pfail_log2={}", block_params.log2_p_fail);

    let (runs_for_expected_fails, expected_fails) = if should_run_long_pfail_tests() {
        let total_runs = 1_000_000;
        let expected_fails = (total_runs as f64 * expected_pfail).round() as u32;
        (total_runs, expected_fails)
    } else {
        let expected_fails = 200;
        let runs_for_expected_fails = (expected_fails as f64 / expected_pfail).round() as u32;
        (runs_for_expected_fails, expected_fails)
    };
    println!("runs_for_expected_fails={runs_for_expected_fails}");

    // Disable the auto casting in the keyswitching key to be able to measure things ourselves
    cpke_params.expansion_kind =
        CompactCiphertextListExpansionKind::NoCasting(block_params.encryption_key_choice.into());
    // Remove mutability
    let cpke_params = cpke_params;

    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let scalar_for_multiplication = block_params.max_noise_level().get();

    let compact_encryption_secret_key = CompactPrivateKey::new(cpke_params);
    let cpk = CompactPublicKey::new(&compact_encryption_secret_key);

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);

    let ksk = KeySwitchingKey::new(
        (&compact_encryption_secret_key, None),
        (&cks, &sks),
        ksk_params,
    );

    let measured_fails: f64 = (0..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;

            pke_encrypt_ks_to_compute_pfail_helper(
                cpke_params,
                ksk_params,
                block_params,
                &cpk,
                &ksk,
                &cks,
                &sks,
                msg,
                scalar_for_multiplication,
            )
        })
        .sum();

    let measured_pfail = measured_fails / (runs_for_expected_fails as f64);

    println!("measured_fails={measured_fails}");
    println!("expected_fails={expected_fails}");
    println!("measured_pfail={measured_pfail}");
    println!("expected_pfail={expected_pfail}");

    let equivalent_measured_pfail = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail={equivalent_measured_pfail}");
    println!("original_expected_pfail  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_log2={}",
        equivalent_measured_pfail.log2()
    );
    println!("original_expected_pfail_log2  ={}", original_pfail.log2());

    if measured_fails > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail <= expected_pfail {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters, \
            or some hypothesis does not hold.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_small_pfail() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_small_pfail_zkv1() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
        V1_0_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_pfail() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
        V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_pfail_zkv1() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
        V1_0_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[derive(Clone, Copy, Debug)]
enum CompressionSpecialPfailCase {
    AfterAP {
        decryption_adapted_message_modulus: MessageModulus,
        decryption_adapted_carry_modulus: CarryModulus,
    },
    DoesNotNeedSpecialCase,
}

#[allow(clippy::too_many_arguments)]
fn pbs_compress_and_classic_ap_inner_helper(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    single_decompression_key: &DecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    pfail_special_case: CompressionSpecialPfailCase,
) -> (Vec<DecryptionAndNoiseResult>, Vec<DecryptionAndNoiseResult>) {
    match pfail_special_case {
        CompressionSpecialPfailCase::AfterAP {
            decryption_adapted_message_modulus,
            decryption_adapted_carry_modulus,
        } => {
            let adapted_cleartext_modulus =
                decryption_adapted_carry_modulus.0 * decryption_adapted_message_modulus.0;

            let cleartext_modulus =
                block_params.message_modulus().0 * block_params.carry_modulus().0;

            assert!(
                cleartext_modulus <= adapted_cleartext_modulus,
                "This test only works if the adapted cleartext \
                space is bigger than the original one."
            );
        }
        CompressionSpecialPfailCase::DoesNotNeedSpecialCase => (),
    }

    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let mut engine = ShortintEngine::new();
    let thread_cks;
    let thread_sks;
    let thread_compression_private_key;
    let thread_compression_key;
    let thread_decompression_key;
    let (cks, sks, compression_private_key, compression_key, decompression_key) =
        if should_use_one_key_per_sample() {
            thread_cks = engine.new_client_key(block_params);
            thread_sks = engine.new_server_key(&thread_cks);
            thread_compression_private_key =
                thread_cks.new_compression_private_key(compression_params);
            (thread_compression_key, thread_decompression_key) =
                thread_cks.new_compression_decompression_keys(&thread_compression_private_key);

            (
                &thread_cks,
                &thread_sks,
                &thread_compression_private_key,
                &thread_compression_key,
                &thread_decompression_key,
            )
        } else {
            // If we don't want to use per thread keys (to go faster), we use those single keys for
            // all threads
            (
                single_cks,
                single_sks,
                single_compression_private_key,
                single_compression_key,
                single_decompression_key,
            )
        };

    // We can only store values under message_modulus with the current compression scheme.
    let encryption_cleartext_modulus =
        block_params.message_modulus().0 * block_params.carry_modulus().0;
    let encryption_delta = (1u64 << 63) / encryption_cleartext_modulus;

    // We multiply by the message_modulus during compression, so the top bits corresponding to the
    // modulus won't be usable during compression
    let compression_cleartext_modulus =
        encryption_cleartext_modulus / block_params.message_modulus().0;
    let compression_delta = (1u64 << 63) / compression_cleartext_modulus;
    let msg = msg % compression_cleartext_modulus;

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let compute_br_input_modulus_log = bootstrapping_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native = u64::BITS - compute_br_input_modulus_log.0 as u32;
    let compute_br_input_modulus =
        CiphertextModulus::try_new_power_of_2(compute_br_input_modulus_log.0).unwrap();
    let no_noise_distribution = DynamicDistribution::new_gaussian(Variance(0.0));
    let br_modulus_delta =
        compute_br_input_modulus.get_custom_modulus() as u64 / (2 * encryption_cleartext_modulus);

    // Prepare the max number of LWE to pack, encrypt them under the compute PBS input modulus (2N)
    // without noise

    let ciphertexts = (0..compression_key.lwe_per_glwe.0)
        .into_par_iter()
        .map(|_| {
            let mut engine = ShortintEngine::new();

            let mut shortint_ct = sks.create_trivial(0);

            // Encrypt noiseless under 2N
            let encrypted_lwe_under_br_modulus = {
                let under_br_modulus = allocate_and_encrypt_new_lwe_ciphertext(
                    &cks.small_lwe_secret_key(),
                    Plaintext(msg * br_modulus_delta),
                    no_noise_distribution,
                    compute_br_input_modulus,
                    &mut engine.encryption_generator,
                );

                // Return it under the native modulus, this is valid as power of 2 encoding puts
                // everything in the MSBs
                LweCiphertext::from_container(
                    under_br_modulus.into_container(),
                    shortint_ct.ct.ciphertext_modulus(),
                )
            };

            let identity_lut = sks.generate_lookup_table(|x| x);

            let buffers = engine.get_computation_buffers();

            // Apply the PBS to get out noisy and under the proper encryption key
            // and no modulus switch noise reduction as we have a noiseless input ciphertext
            apply_programmable_bootstrap_no_ms_noise_reduction(
                bootstrapping_key,
                &encrypted_lwe_under_br_modulus,
                &mut shortint_ct.ct,
                &identity_lut.acc,
                buffers,
            );

            shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

            shortint_ct
        })
        .collect::<Vec<_>>();

    // Do the compression process
    let compressed_list = compression_key.compress_ciphertexts_into_list(&ciphertexts);
    assert_eq!(
        compressed_list.modulus_switched_glwe_ciphertext_list.len(),
        1
    );
    let packed_glwe = compressed_list.modulus_switched_glwe_ciphertext_list[0].clone();

    let glwe = packed_glwe.extract();

    let glwe_equivalent_lwe_dimension = glwe
        .glwe_size()
        .to_glwe_dimension()
        .to_equivalent_lwe_dimension(glwe.polynomial_size());

    let mut lwes = vec![
        LweCiphertext::new(
            0u64,
            glwe_equivalent_lwe_dimension.to_lwe_size(),
            glwe.ciphertext_modulus()
        );
        glwe.polynomial_size().0
    ];

    // Get the individual LWE ciphertexts back under the storage modulus
    for (index, output_lwe) in lwes.iter_mut().enumerate() {
        extract_lwe_sample_from_glwe_ciphertext(&glwe, output_lwe, MonomialDegree(index));
    }

    let after_compression_result: Vec<_> = lwes
        .into_iter()
        .map(|lwe| {
            DecryptionAndNoiseResult::new(
                &lwe,
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                msg,
                compression_delta,
                compression_cleartext_modulus,
            )
        })
        .collect();

    let lwe_per_glwe = compressed_list.lwe_per_glwe.0;
    let after_ap_lwe: Vec<_> = (0..lwe_per_glwe)
        .into_par_iter()
        .map(|index| {
            let mut decompressed = decompression_key.unpack(&compressed_list, index).unwrap();
            // Strictly remove the plaintext to avoid wrong results during the mul
            lwe_ciphertext_plaintext_sub_assign(
                &mut decompressed.ct,
                Plaintext(msg * encryption_delta),
            );
            sks.unchecked_scalar_mul_assign(
                &mut decompressed,
                scalar_for_multiplication.try_into().unwrap(),
            );
            sks.unchecked_scalar_add_assign(&mut decompressed, msg.try_into().unwrap());

            let mut after_ks_lwe = LweCiphertext::new(
                0u64,
                key_switching_key.output_lwe_size(),
                key_switching_key.ciphertext_modulus(),
            );

            keyswitch_lwe_ciphertext(&key_switching_key, &decompressed.ct, &mut after_ks_lwe);

            // The previous computations were:
            // PBS -> Packing KS -> Storage MS -> BR to decompress -> KS | We are here
            // So we need to apply the drift noise reduction technique and then the mod switch
            match bootstrapping_key {
                ShortintBootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => {
                    let mut after_ms = apply_modulus_switch_noise_reduction(
                        modulus_switch_noise_reduction_key.as_ref().unwrap(),
                        compute_br_input_modulus_log,
                        &after_ks_lwe,
                    );

                    for val in after_ms.as_mut().iter_mut() {
                        *val = modulus_switch(*val, compute_br_input_modulus_log)
                            << shift_to_map_to_native;
                    }

                    after_ms
                }
                ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
            }
        })
        .collect();

    let (expected_msg, decryption_delta, decryption_cleartext_modulus) = match pfail_special_case {
        CompressionSpecialPfailCase::AfterAP {
            decryption_adapted_message_modulus,
            decryption_adapted_carry_modulus,
        } => {
            let adapted_cleartext_modulus =
                decryption_adapted_message_modulus.0 * decryption_adapted_carry_modulus.0;
            let adapted_delta = (1u64 << 63) / adapted_cleartext_modulus;
            let delta_diff = encryption_delta / adapted_delta;
            let expected_msg = msg * delta_diff;

            (expected_msg, adapted_delta, adapted_cleartext_modulus)
        }
        CompressionSpecialPfailCase::DoesNotNeedSpecialCase => {
            (msg, encryption_delta, encryption_cleartext_modulus)
        }
    };

    let after_ap_result: Vec<_> = after_ap_lwe
        .into_iter()
        .map(|lwe| {
            DecryptionAndNoiseResult::new(
                &lwe,
                &cks.small_lwe_secret_key(),
                expected_msg,
                decryption_delta,
                decryption_cleartext_modulus,
            )
        })
        .collect();

    (after_compression_result, after_ap_result)
}

#[allow(clippy::too_many_arguments)]
fn pbs_compress_and_classic_ap_noise_helper(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    single_decompression_key: &DecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (Vec<NoiseSample>, Vec<NoiseSample>) {
    let (decryption_and_noise_result_after_compression, decryption_and_noise_result_after_ap) =
        pbs_compress_and_classic_ap_inner_helper(
            block_params,
            compression_params,
            single_cks,
            single_sks,
            single_compression_private_key,
            single_compression_key,
            single_decompression_key,
            msg,
            scalar_for_multiplication,
            CompressionSpecialPfailCase::DoesNotNeedSpecialCase,
        );

    (
        decryption_and_noise_result_after_compression
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            })
            .collect(),
        decryption_and_noise_result_after_ap
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            })
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn pbs_compress_and_classic_ap_pfail_helper(
    block_params: ShortintParameterSet,
    compression_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    single_decompression_key: &DecompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
    pfail_special_case: CompressionSpecialPfailCase,
) -> (Vec<f64>, Vec<f64>) {
    let (decryption_and_noise_result_after_compression, decryption_and_noise_result_after_ap) =
        pbs_compress_and_classic_ap_inner_helper(
            block_params,
            compression_params,
            single_cks,
            single_sks,
            single_compression_private_key,
            single_compression_key,
            single_decompression_key,
            msg,
            scalar_for_multiplication,
            pfail_special_case,
        );

    (
        decryption_and_noise_result_after_compression
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
                DecryptionAndNoiseResult::DecryptionFailed => 1.0,
            })
            .collect(),
        decryption_and_noise_result_after_ap
            .into_iter()
            .map(|x| match x {
                DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
                DecryptionAndNoiseResult::DecryptionFailed => 1.0,
            })
            .collect(),
    )
}

fn noise_check_shortint_pbs_compression_ap_noise(
    block_params: ClassicPBSParameters,
    compression_params: CompressionParameters,
) {
    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);

    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&compression_private_key);

    let (key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let compute_ks_input_lwe_dimension = key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = key_switching_key.decomposition_level_count();

    let compute_pbs_input_lwe_dimension = bootstrapping_key.input_lwe_dimension();
    let compute_pbs_output_glwe_dimension = bootstrapping_key.glwe_size().to_glwe_dimension();
    let compute_pbs_output_polynomial_size = bootstrapping_key.polynomial_size();
    let compute_pbs_decomp_base_log = bootstrapping_key.decomposition_base_log();
    let compute_pbs_decomp_level_count = bootstrapping_key.decomposition_level_count();

    let scalar_for_ap_multiplication = block_params.max_noise_level().get();

    let ap_br_input_modulus_log = block_params
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let ap_br_input_modulus = 1u64 << ap_br_input_modulus_log.0;

    let expected_variance_after_compute_pbs = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            compute_pbs_input_lwe_dimension,
            compute_pbs_output_glwe_dimension,
            compute_pbs_output_polynomial_size,
            compute_pbs_decomp_base_log,
            compute_pbs_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            compute_pbs_input_lwe_dimension,
            compute_pbs_output_glwe_dimension,
            compute_pbs_output_polynomial_size,
            compute_pbs_decomp_base_log,
            compute_pbs_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let multiplication_factor_before_packing_ks = block_params.message_modulus().0;

    let expected_variance_after_msg_shif_to_msb = scalar_multiplication_variance(
        expected_variance_after_compute_pbs,
        multiplication_factor_before_packing_ks,
    );

    let pksk_input_lwe_dimension = compression_key
        .packing_key_switching_key
        .input_key_lwe_dimension();
    let pksk_output_glwe_dimension = compression_key
        .packing_key_switching_key
        .output_glwe_size()
        .to_glwe_dimension();
    let pksk_output_polynomial_size = compression_key
        .packing_key_switching_key
        .output_polynomial_size();
    let pksk_decomp_base_log = compression_key
        .packing_key_switching_key
        .decomposition_base_log();
    let pksk_decomp_level_count = compression_key
        .packing_key_switching_key
        .decomposition_level_count();
    let pksk_output_lwe_dimension =
        pksk_output_glwe_dimension.to_equivalent_lwe_dimension(pksk_output_polynomial_size);

    let lwe_to_pack = compression_key.lwe_per_glwe.0;

    let packing_keyswitch_additive_variance =
        match compression_params.packing_ks_key_noise_distribution {
            DynamicDistribution::Gaussian(_) => {
                packing_keyswitch_additive_variance_132_bits_security_gaussian(
                    pksk_input_lwe_dimension,
                    pksk_output_glwe_dimension,
                    pksk_output_polynomial_size,
                    pksk_decomp_base_log,
                    pksk_decomp_level_count,
                    lwe_to_pack as f64,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                packing_keyswitch_additive_variance_132_bits_security_tuniform(
                    pksk_input_lwe_dimension,
                    pksk_output_glwe_dimension,
                    pksk_output_polynomial_size,
                    pksk_decomp_base_log,
                    pksk_decomp_level_count,
                    lwe_to_pack as f64,
                    modulus_as_f64,
                )
            }
        };

    let expected_variance_after_pks =
        Variance(expected_variance_after_msg_shif_to_msb.0 + packing_keyswitch_additive_variance.0);

    let compression_storage_modulus = 1u64 << compression_key.storage_log_modulus.0;
    let compression_storage_modulus_as_f64 = compression_storage_modulus as f64;

    // For compression we do not apply the generalized mod switch
    let storage_modulus_switch_additive_variance = modulus_switch_additive_variance(
        pksk_output_lwe_dimension,
        modulus_as_f64,
        compression_storage_modulus_as_f64,
    );

    let expected_variance_after_storage_modulus_switch =
        Variance(expected_variance_after_pks.0 + storage_modulus_switch_additive_variance.0);

    let decompression_br_input_lwe_dimension =
        decompression_key.blind_rotate_key.input_lwe_dimension();
    let decompression_br_output_glwe_dimension = decompression_key
        .blind_rotate_key
        .glwe_size()
        .to_glwe_dimension();
    let decompression_br_output_polynomial_size =
        decompression_key.blind_rotate_key.polynomial_size();
    let decompression_br_base_log = decompression_key.blind_rotate_key.decomposition_base_log();
    let decompression_br_level_count = decompression_key
        .blind_rotate_key
        .decomposition_level_count();

    // Starting decompression, we RESET the noise with a PBS
    // We return under the key of the compute AP so check the associated GLWE noise distribution
    let expected_variance_after_decompression = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            decompression_br_input_lwe_dimension,
            decompression_br_output_glwe_dimension,
            decompression_br_output_polynomial_size,
            decompression_br_base_log,
            decompression_br_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            decompression_br_input_lwe_dimension,
            decompression_br_output_glwe_dimension,
            decompression_br_output_polynomial_size,
            decompression_br_base_log,
            decompression_br_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ap_max_mul = scalar_multiplication_variance(
        expected_variance_after_decompression,
        scalar_for_ap_multiplication,
    );

    // Now keyswitch
    let ap_ks_additive_variance = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            modulus_as_f64,
        ),
    };

    let expected_variance_after_ap_ks =
        Variance(expected_variance_after_ap_max_mul.0 + ap_ks_additive_variance.0);

    // TODO output noise after drift mitigation, check normality
    let drift_mitigation_additive_var = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_after_ap_ks.0 + drift_mitigation_additive_var.0);

    let ap_ms_additive_variance = generalized_modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        modulus_as_f64,
        ap_br_input_modulus as f64,
    );

    let expected_variance_after_ap_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ap_ms_additive_variance.0);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_after_compression = vec![];
    let mut noise_samples_after_ap = vec![];

    let sample_count_per_msg = 1000;

    let number_of_runs = sample_count_per_msg.div_ceil(compression_key.lwe_per_glwe.0);
    for msg in 0..cleartext_modulus {
        let (current_noise_samples_after_compression, current_noise_samples_after_ap): (
            Vec<_>,
            Vec<_>,
        ) = (0..number_of_runs)
            .into_par_iter()
            .map(|_| {
                pbs_compress_and_classic_ap_noise_helper(
                    block_params,
                    compression_params,
                    &cks,
                    &sks,
                    &compression_private_key,
                    &compression_key,
                    &decompression_key,
                    msg,
                    scalar_for_ap_multiplication,
                )
            })
            .unzip();

        noise_samples_after_compression.extend(
            current_noise_samples_after_compression
                .into_iter()
                .flatten()
                .map(|x| x.value),
        );

        noise_samples_after_ap.extend(
            current_noise_samples_after_ap
                .into_iter()
                .flatten()
                .map(|x| x.value),
        );
    }

    println!();

    let after_compression_is_ok = mean_and_variance_check(
        &noise_samples_after_compression,
        "after_compression",
        0.0,
        expected_variance_after_storage_modulus_switch,
        compression_params.packing_ks_key_noise_distribution,
        compression_private_key
            .post_packing_ks_key
            .as_lwe_secret_key()
            .lwe_dimension(),
        modulus_as_f64,
    );

    let after_ap_is_ok = mean_and_variance_check(
        &noise_samples_after_ap,
        "after_ap",
        0.0,
        expected_variance_after_ap_ms,
        block_params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        modulus_as_f64,
    );

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);

    assert!(after_compression_is_ok && after_ap_is_ok);
}

#[test]
fn test_noise_check_shortint_pbs_compression_ap_noise_tuniform() {
    noise_check_shortint_pbs_compression_ap_noise(
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_pbs_compression_ap_pfail(
    block_params: ClassicPBSParameters,
    compression_params: CompressionParameters,
) {
    assert_eq!(
        block_params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus.0 * block_params.message_modulus.0).ilog2();

    // We are going to check if the decryption works well under adapted moduli that will tweak the
    // pfail.
    let decryption_adapted_message_modulus = block_params.message_modulus;
    let decryption_adapted_carry_modulus = CarryModulus(1 << 4);

    let new_precision_with_padding =
        (2 * decryption_adapted_message_modulus.0 * decryption_adapted_carry_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail);

    let expected_pfail_after_ap = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_after_ap_log2 = expected_pfail_after_ap.log2();

    println!("expected_pfail_after_ap={expected_pfail_after_ap}");
    println!("expected_pfail_after_ap_log2={expected_pfail_after_ap_log2}");

    let samples_per_run = compression_params.lwe_per_glwe.0;

    let (expected_fails_after_ap, runs_for_expected_fails, total_sample_count) =
        if should_run_long_pfail_tests() {
            let target_sample_count = 1_000_000;
            let runs_count = target_sample_count.div_ceil(samples_per_run);
            let actual_sample_count = runs_count * samples_per_run;
            let expected_fails_after_ap =
                (expected_pfail_after_ap * actual_sample_count as f64).round() as u32;
            (expected_fails_after_ap, runs_count, actual_sample_count)
        } else {
            let expected_fails_after_ap = 200;

            let runs_for_expected_fails = (expected_fails_after_ap as f64
                / (expected_pfail_after_ap * samples_per_run as f64))
                .round() as usize;

            let total_sample_count = runs_for_expected_fails * samples_per_run;
            (
                expected_fails_after_ap,
                runs_for_expected_fails,
                total_sample_count,
            )
        };

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let scalar_for_multiplication = block_params.max_noise_level().get();

    let encryption_cleartext_modulus =
        block_params.message_modulus().0 * block_params.carry_modulus().0;
    // We multiply by the message_modulus during compression, so the top bits corresponding to the
    // modulus won't be usable during compression
    let compression_cleartext_modulus =
        encryption_cleartext_modulus / block_params.message_modulus().0;

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);

    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&compression_private_key);

    let (_measured_fails_after_compression, measured_fails_after_ap): (Vec<_>, Vec<_>) = (0
        ..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % compression_cleartext_modulus;

            pbs_compress_and_classic_ap_pfail_helper(
                block_params,
                compression_params,
                &cks,
                &sks,
                &compression_private_key,
                &compression_key,
                &decompression_key,
                msg,
                scalar_for_multiplication,
                CompressionSpecialPfailCase::AfterAP {
                    decryption_adapted_message_modulus,
                    decryption_adapted_carry_modulus,
                },
            )
        })
        .unzip();

    let measured_fails_after_ap: f64 = measured_fails_after_ap.into_iter().flatten().sum();
    let measured_pfail_after_ap = measured_fails_after_ap / (total_sample_count as f64);

    println!("measured_fails_after_ap={measured_fails_after_ap}");
    println!("measured_pfail_after_ap={measured_pfail_after_ap}");
    println!("expected_fails_after_ap={expected_fails_after_ap}");
    println!("expected_pfail_after_ap={expected_pfail_after_ap}");

    let equivalent_measured_pfail_after_ap = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail_after_ap,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail_after_ap={equivalent_measured_pfail_after_ap}");
    println!("original_expected_pfail_after_ap  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_after_ap_log2={}",
        equivalent_measured_pfail_after_ap.log2()
    );
    println!(
        "original_expected_pfail_after_ap_log2  ={}",
        original_pfail.log2()
    );

    if measured_fails_after_ap > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_after_ap,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail_after_ap <= expected_pfail_after_ap {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ap) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ap));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_shortint_pbs_compression_ap_after_ap_pfail_tuniform() {
    noise_check_shortint_pbs_compression_ap_pfail(
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail(
    mut block_params: ClassicPBSParameters,
    compression_params: CompressionParameters,
) {
    assert_eq!(
        block_params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    let block_params_log2_pfail = block_params.log2_p_fail;

    let original_message_modulus = block_params.message_modulus;
    let original_carry_modulus = block_params.carry_modulus;

    let encryption_cleartext_modulus = original_message_modulus.0 * original_carry_modulus.0;
    // We multiply by message modulus before compression
    let original_compression_cleartext_modulus =
        encryption_cleartext_modulus / original_message_modulus.0;

    // We are going to simulate 6 bits to measure the pfail of compression
    // To avoid a multiplication we set the message modulus to 1 and put everything in the carry
    // modulus
    block_params.message_modulus = MessageModulus(1);
    block_params.carry_modulus = CarryModulus(1 << 6);

    let block_params = block_params;

    let modified_encryption_modulus = block_params.message_modulus.0 * block_params.carry_modulus.0;

    let samples_per_run = compression_params.lwe_per_glwe.0;

    let (run_count, total_sample_count) = if should_run_long_pfail_tests() {
        let target_sample_count = 1_000_000;
        let run_count = target_sample_count.div_ceil(samples_per_run);
        let actual_sample_count = run_count * samples_per_run;
        (run_count, actual_sample_count)
    } else {
        let run_count = 500;
        let total_sample_count = run_count * samples_per_run;
        (run_count, total_sample_count)
    };

    println!("run_count={run_count}");
    println!("total_sample_count={total_sample_count}");

    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let scalar_for_multiplication = block_params.max_noise_level().get();

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);

    let compression_private_key = cks.new_compression_private_key(compression_params);
    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&compression_private_key);

    let (measured_fails_after_ms_storage, _measured_fails_after_ap): (Vec<_>, Vec<_>) = (0
        ..run_count)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % modified_encryption_modulus;

            pbs_compress_and_classic_ap_pfail_helper(
                block_params,
                compression_params,
                &cks,
                &sks,
                &compression_private_key,
                &compression_key,
                &decompression_key,
                msg,
                scalar_for_multiplication,
                CompressionSpecialPfailCase::DoesNotNeedSpecialCase,
            )
        })
        .unzip();

    let measured_fails_after_ms_storage: f64 =
        measured_fails_after_ms_storage.into_iter().flatten().sum();
    let measured_pfail_after_ms_storage =
        measured_fails_after_ms_storage / (total_sample_count as f64);

    let measured_pfail_after_ms_storage_log2 = measured_pfail_after_ms_storage.log2();

    println!("measured_fails_after_ms_storage={measured_fails_after_ms_storage}");
    println!("measured_pfail_after_ms_storage={measured_pfail_after_ms_storage}");
    println!("measured_pfail_after_ms_storage_log2={measured_pfail_after_ms_storage_log2}");

    let precision_used_during_compression =
        1 + (block_params.message_modulus().0 * block_params.carry_modulus().0).ilog2();

    // We want to estimate the pfail under the original modulus with the one under the modified
    // precision_used_during_compression
    let equivalent_measured_pfail_ms_storage = equivalent_pfail_gaussian_noise(
        precision_used_during_compression,
        measured_pfail_after_ms_storage,
        1 + original_compression_cleartext_modulus.ilog2(),
    );

    let equivalent_measured_pfail_ms_storage_log2 = equivalent_measured_pfail_ms_storage.log2();

    println!("equivalent_measured_pfail_ms_storage={equivalent_measured_pfail_ms_storage}");
    println!(
        "equivalent_measured_pfail_ms_storage_log2={equivalent_measured_pfail_ms_storage_log2}"
    );

    let original_pfail = 2.0f64.powf(block_params_log2_pfail);

    println!("original_expected_pfail_after_ms_storage={original_pfail}");
    println!(
        "original_expected_pfail_after_after_ms_storage={}",
        original_pfail.log2()
    );

    assert!(equivalent_measured_pfail_ms_storage <= 2.0f64.powf(block_params_log2_pfail));

    // if measured_fails_after_ms_storage > 0.0 {
    //     let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
    //         total_sample_count as f64,
    //         measured_fails_after_ms_storage,
    //         0.99,
    //     );

    //     println!(
    //         "pfail_lower_bound={}",
    //         pfail_confidence_interval.lower_bound()
    //     );
    //     println!(
    //         "pfail_upper_bound={}",
    //         pfail_confidence_interval.upper_bound()
    //     );

    //     if measured_pfail_after_ms_storage <= expected_pfail_after_ms_storage {
    //         if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_after_ms_storage) {
    //             println!(
    //                 "\n==========\n\
    //                 WARNING: measured pfail is smaller than expected pfail \
    //                 and out of the confidence interval\n\
    //                 the optimizer might be pessimistic when generating parameters.\n\
    //                 ==========\n"
    //             );
    //         }
    //     } else {
    //         assert!(pfail_confidence_interval.
    // mean_is_in_interval(expected_pfail_after_ms_storage));     }
    // } else {
    //     println!(
    //         "\n==========\n\
    //         WARNING: measured pfail is 0, it is either a bug or \
    //         it is way smaller than the expected pfail\n\
    //         the optimizer might be pessimistic when generating parameters.\n\
    //         ==========\n"
    //     );
    // }
}

#[test]
fn test_noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail_tuniform() {
    noise_check_shortint_pbs_compression_ap_after_ms_storage_pfail(
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn mean_and_variance_check<Scalar: UnsignedInteger>(
    noise_samples: &[f64],
    suffix: &str,
    expected_mean: f64,
    expected_variance: Variance,
    noise_distribution_used_for_encryption: DynamicDistribution<Scalar>,
    decryption_key_lwe_dimension: LweDimension,
    modulus_as_f64: f64,
) -> bool {
    let measured_mean = arithmetic_mean(noise_samples);
    let measured_variance = variance(noise_samples);

    let mean_ci = mean_confidence_interval(
        noise_samples.len() as f64,
        measured_mean,
        measured_variance.get_standard_dev(),
        0.99,
    );

    let variance_ci =
        variance_confidence_interval(noise_samples.len() as f64, measured_variance, 0.99);

    println!("measured_variance_{suffix}={measured_variance:?}");
    println!("expected_variance_{suffix}={expected_variance:?}");
    println!("variance_lower_bound={:?}", variance_ci.lower_bound());
    println!("variance_upper_bound={:?}", variance_ci.upper_bound());
    println!("measured_mean_{suffix}={measured_mean:?}");
    println!("expected_mean_{suffix}={expected_mean:?}");
    println!("mean_{suffix}_lower_bound={:?}", mean_ci.lower_bound());
    println!("mean_{suffix}_upper_bound={:?}", mean_ci.upper_bound());

    // Expected mean is 0
    let mean_is_in_interval = mean_ci.mean_is_in_interval(expected_mean);

    if mean_is_in_interval {
        println!(
            "PASS: measured_mean_{suffix} confidence interval \
            contains the expected mean"
        );
    } else {
        println!(
            "FAIL: measured_mean_{suffix} confidence interval \
            does not contain the expected mean"
        );
    }

    // We want to be smaller but secure or in the interval
    let variance_is_ok = if measured_variance <= expected_variance {
        let noise_for_security = match noise_distribution_used_for_encryption {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    decryption_key_lwe_dimension,
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    decryption_key_lwe_dimension,
                    modulus_as_f64,
                )
            }
        };

        let variance_is_secure = measured_variance >= noise_for_security;

        if variance_is_secure {
            println!("PASS: measured_variance_{suffix} is smaller than expected variance.");

            if !variance_ci.variance_is_in_interval(expected_variance) {
                println!(
                    "\n==========\n\
                    Warning: noise formula might be over estimating the noise.\n\
                    ==========\n"
                );
            }
        } else {
            println!("FAIL:measured_variance_{suffix} is NOT secure.")
        }

        variance_is_secure
    } else {
        let interval_ok = variance_ci.variance_is_in_interval(expected_variance);

        if interval_ok {
            println!(
                "PASS: measured_variance_{suffix} confidence interval \
                contains the expected variance"
            );
        } else {
            println!(
                "FAIL: measured_variance_{suffix} confidence interval \
                does not contain the expected variance"
            );
        }

        interval_ok
    };

    mean_is_in_interval && variance_is_ok
}

#[derive(Clone, Copy, Debug)]
enum PBS128InputBRParams {
    Decompression { params: CompressionParameters },
    Compute,
}

#[derive(Clone, Copy, Debug)]
struct PBS128Parameters {
    input_lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    glwe_noise_distribution: DynamicDistribution<u128>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
    // There was a doubt on the mantissa size, several experiments were conducted
    mantissa_size: f64,
    ciphertext_modulus: CoreCiphertextModulus<u128>,
}

const PBS128_PARAMS: PBS128Parameters = PBS128Parameters {
    input_lwe_dimension: LweDimension(918),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
        modulus_switch_zeros_count: LweCiphertextCount(1449),
        ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
        ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
        ms_input_variance: Variance(2.63039184094559E-7f64),
    }),
    mantissa_size: 104f64,
    // 2^128
    ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
};

// #[test]
// fn test_noise_check_pbs_128_secure_noise() {
//     let params = PBS128_PARAMS;

//     let modulus_as_f64 = if params.ciphertext_modulus.is_native_modulus() {
//         2.0f64.powi(128)
//     } else {
//         params.ciphertext_modulus.get_custom_modulus() as f64
//     };

//     let tuniform_bound = minimal_glwe_bound_for_132_bits_security_tuniform(
//         params.glwe_dimension,
//         params.polynomial_size,
//         modulus_as_f64,
//     );

//     match params.glwe_noise_distribution {
//         DynamicDistribution::Gaussian(_) => panic!("Only TUniform is checked here"),
//         DynamicDistribution::TUniform(tuniform) => {
//             assert_eq!(tuniform.bound_log2(), tuniform_bound.0.log2() as i32)
//         }
//     }
// }

#[allow(clippy::too_many_arguments)]
fn br_to_squash_pbs_128_inner_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey<u64>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_before_pbs_128_ms_noise_reduction_key: Option<&ModulusSwitchNoiseReductionKey<u64>>,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
) -> (
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    assert!(pbs128_params
        .modulus_switch_noise_reduction_params
        .is_some());
    assert!(block_params.pbs_only());
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let mut engine = ShortintEngine::new();
    let thread_compression_private_key;
    let thread_decompression_key;
    let thread_cks;
    let thread_sks;
    let thread_encryption_key;
    let thread_input_br_key;
    let thread_before_pbs_128_ms_noise_reduction_key;
    let thread_pbs_128_key;
    let thread_output_pbs_128_glwe_secret_key;
    let (
        cks,
        sks,
        encryption_key,
        input_br_key,
        before_pbs_128_ms_noise_reduction_key,
        pbs_128_key,
        output_pbs_128_glwe_secret_key,
    ) = if should_use_one_key_per_sample() {
        thread_cks = engine.new_client_key(block_params);
        thread_sks = engine.new_server_key(&thread_cks);
        thread_before_pbs_128_ms_noise_reduction_key = pbs128_params
            .modulus_switch_noise_reduction_params
            .map(|ms_param| {
                ModulusSwitchNoiseReductionKey::new(
                    ms_param,
                    &thread_cks.small_lwe_secret_key(),
                    &mut engine,
                    block_params.ciphertext_modulus(),
                    block_params.lwe_noise_distribution(),
                )
            });

        (thread_encryption_key, thread_input_br_key) = match input_br_params {
            PBS128InputBRParams::Decompression { params } => {
                thread_compression_private_key = thread_cks.new_compression_private_key(params);
                thread_decompression_key = thread_cks
                    .new_compression_decompression_keys(&thread_compression_private_key)
                    .1;

                (
                    thread_compression_private_key
                        .post_packing_ks_key
                        .as_lwe_secret_key(),
                    &thread_decompression_key.blind_rotate_key,
                )
            }
            PBS128InputBRParams::Compute => {
                let (_key_switching_key, bootstrapping_key) = match &thread_sks.atomic_pattern {
                    AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
                        standard_atomic_pattern_server_key
                            .key_switching_key
                            .as_view(),
                        &standard_atomic_pattern_server_key.bootstrapping_key,
                    ),
                    AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
                    AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
                };
                (thread_cks.small_lwe_secret_key(), bootstrapping_key)
            }
        };

        thread_pbs_128_key = {
            let thread_input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
                thread_cks
                    .small_lwe_secret_key()
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|x| x as u128)
                    .collect::<Vec<_>>(),
            );

            thread_output_pbs_128_glwe_secret_key =
                allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
                    pbs128_params.glwe_dimension,
                    pbs128_params.polynomial_size,
                    &mut engine.secret_generator,
                );

            let std_bootstrapping_key =
                par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _, _>(
                    &thread_input_lwe_secret_key_as_u128,
                    &thread_output_pbs_128_glwe_secret_key,
                    pbs128_params.decomp_base_log,
                    pbs128_params.decomp_level_count,
                    pbs128_params.glwe_noise_distribution,
                    pbs128_params.ciphertext_modulus,
                    &mut engine.encryption_generator,
                );

            let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                std_bootstrapping_key.input_lwe_dimension(),
                std_bootstrapping_key.glwe_size(),
                std_bootstrapping_key.polynomial_size(),
                std_bootstrapping_key.decomposition_base_log(),
                std_bootstrapping_key.decomposition_level_count(),
            );

            convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fbsk);

            fbsk
        };

        (
            &thread_cks,
            &thread_sks,
            &thread_encryption_key,
            thread_input_br_key,
            thread_before_pbs_128_ms_noise_reduction_key.as_ref(),
            &thread_pbs_128_key,
            &thread_output_pbs_128_glwe_secret_key.as_view(),
        )
    } else {
        // If we don't want to use per thread keys (to go faster), we use those single keys for
        // all threads
        (
            single_cks,
            single_sks,
            single_encryption_key,
            single_input_br_key,
            single_before_pbs_128_ms_noise_reduction_key,
            single_pbs_128_key,
            single_output_pbs_128_glwe_secret_key,
        )
    };

    let (key_switching_key, _bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let br_input_modulus_log = input_br_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native_u64_before_pbs_128 = u64::BITS - br_128_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;
    let delta_u128 = (1u128 << 127) / cleartext_modulus as u128;

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let input_pbs_lwe_ct = {
        let ms_modulus = CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();
        let no_noise_dist = DynamicDistribution::new_gaussian(Variance(0.0));

        let ms_delta = ms_modulus.get_custom_modulus() as u64 / (2 * cleartext_modulus);

        let ms_plaintext = Plaintext(msg * ms_delta);

        let simulated_mod_switch_ct = allocate_and_encrypt_new_lwe_ciphertext(
            encryption_key,
            ms_plaintext,
            no_noise_dist,
            ms_modulus,
            &mut engine.encryption_generator,
        );

        let raw_data = simulated_mod_switch_ct.into_container();
        // Now get the noiseless mod switched encryption under the proper modulus
        // The power of 2 modulus are always encrypted in the MSBs, so this is fine
        LweCiphertext::from_container(raw_data, block_params.ciphertext_modulus())
    };

    let mut after_pbs_shortint_ct = sks.unchecked_create_trivial_with_lwe_size(
        Cleartext(0),
        input_br_key.output_lwe_dimension().to_lwe_size(),
    );

    let buffers = engine.get_computation_buffers();

    // Apply the PBS only and no modulus switch noise reduction as we have a noiseless input
    // ciphertext
    apply_programmable_bootstrap_no_ms_noise_reduction(
        input_br_key,
        &input_pbs_lwe_ct,
        &mut after_pbs_shortint_ct.ct,
        &identity_lut.acc,
        buffers,
    );

    after_pbs_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    lwe_ciphertext_plaintext_sub_assign(&mut after_pbs_shortint_ct.ct, Plaintext(msg * delta));

    sks.unchecked_scalar_mul_assign(&mut after_pbs_shortint_ct, scalar_for_multiplication);

    sks.unchecked_scalar_add_assign(&mut after_pbs_shortint_ct, msg.try_into().unwrap());

    let mut after_ks_lwe = LweCiphertext::new(
        0u64,
        key_switching_key.output_lwe_size(),
        key_switching_key.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext(
        &key_switching_key,
        &after_pbs_shortint_ct.ct,
        &mut after_ks_lwe,
    );

    let before_ms = before_pbs_128_ms_noise_reduction_key.map_or_else(
        || after_ks_lwe.clone(),
        |before_pbs_128_ms_noise_reduction_key| {
            apply_modulus_switch_noise_reduction(
                before_pbs_128_ms_noise_reduction_key,
                br_128_input_modulus_log,
                &after_ks_lwe,
            )
        },
    );

    let mut input_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.input_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );

    assert_eq!(input_pbs_128.lwe_size(), before_ms.lwe_size());

    // Map the u64 to u128 because the pbs 128 currently does not support different input and scalar
    // types
    for (dst, src) in input_pbs_128
        .as_mut()
        .iter_mut()
        .zip(before_ms.as_ref().iter())
    {
        *dst = (*src as u128) << 64;
    }

    let mut after_ms = before_ms.clone();

    for val in after_ms.as_mut().iter_mut() {
        *val = modulus_switch(*val, br_128_input_modulus_log)
            << shift_to_map_to_native_u64_before_pbs_128;
    }

    let mut output_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.output_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );

    let acc = generate_programmable_bootstrap_glwe_lut(
        pbs_128_key.polynomial_size(),
        pbs_128_key.glwe_size(),
        cleartext_modulus as usize,
        pbs128_params.ciphertext_modulus,
        delta_u128,
        |x| x,
    );

    programmable_bootstrap_f128_lwe_ciphertext(
        &input_pbs_128,
        &mut output_pbs_128,
        &acc,
        pbs_128_key,
    );

    (
        // This one is before the drift mitigation
        DecryptionAndNoiseResult::new(
            &after_ks_lwe,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &before_ms,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &after_ms,
            &cks.small_lwe_secret_key(),
            msg,
            delta,
            cleartext_modulus,
        ),
        DecryptionAndNoiseResult::new(
            &output_pbs_128,
            &output_pbs_128_glwe_secret_key.as_lwe_secret_key(),
            msg as u128,
            delta_u128,
            cleartext_modulus as u128,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn br_to_squash_pbs_128_noise_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey<u64>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_before_pbs_128_ms_noise_reduction_key: Option<&ModulusSwitchNoiseReductionKey<u64>>,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
) -> ((NoiseSample, NoiseSample), (NoiseSample, NoiseSample)) {
    let (
        decryption_and_noise_result_before_drift_mitigation,
        decryption_and_noise_result_before_ms_of_pbs_128,
        decryption_and_noise_result_before_pbs_128,
        decryption_and_noise_result_after_pbs_128,
    ) = br_to_squash_pbs_128_inner_helper(
        input_br_params,
        block_params,
        pbs128_params,
        single_encryption_key,
        single_input_br_key,
        single_cks,
        single_sks,
        single_before_pbs_128_ms_noise_reduction_key,
        single_pbs_128_key,
        single_output_pbs_128_glwe_secret_key,
        msg,
        scalar_for_multiplication,
    );

    (
        (
            match decryption_and_noise_result_before_drift_mitigation {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
            match decryption_and_noise_result_before_ms_of_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
        ),
        (
            match decryption_and_noise_result_before_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
            match decryption_and_noise_result_after_pbs_128 {
                DecryptionAndNoiseResult::DecryptionSucceeded { noise } => noise,
                DecryptionAndNoiseResult::DecryptionFailed => {
                    panic!("Failed decryption, noise measurement will be wrong.")
                }
            },
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn br_to_squash_pbs_128_pfail_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey<u64>,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_before_pbs_128_ms_noise_reduction_key: Option<&ModulusSwitchNoiseReductionKey<u64>>,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
    scalar_for_multiplication: u8,
) -> (f64, f64) {
    let (
        _decryption_and_noise_result_before_drift_mitigation,
        _decryption_and_noise_result_before_ms_of_pbs_128,
        decryption_and_noise_result_before_pbs_128,
        decryption_and_noise_result_after_pbs_128,
    ) = br_to_squash_pbs_128_inner_helper(
        input_br_params,
        block_params,
        pbs128_params,
        single_encryption_key,
        single_input_br_key,
        single_cks,
        single_sks,
        single_before_pbs_128_ms_noise_reduction_key,
        single_pbs_128_key,
        single_output_pbs_128_glwe_secret_key,
        msg,
        scalar_for_multiplication,
    );

    (
        match decryption_and_noise_result_before_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
        match decryption_and_noise_result_after_pbs_128 {
            DecryptionAndNoiseResult::DecryptionSucceeded { .. } => 0.0,
            DecryptionAndNoiseResult::DecryptionFailed => 1.0,
        },
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
    input_br_params: PBS128InputBRParams,
    block_params: ClassicPBSParameters,
    pbs128_params: PBS128Parameters,
) {
    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let compute_modulus_as_f64 = if block_params.ciphertext_modulus().is_native_modulus() {
        2.0f64.powi(64)
    } else {
        block_params.ciphertext_modulus().get_custom_modulus() as f64
    };

    let pbs128_output_modulus_as_f64 = if pbs128_params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(128)
    } else {
        pbs128_params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);
    let output_pbs_128_glwe_secret_key;

    let mut engine = ShortintEngine::new();

    let before_pbs_128_ms_noise_reduction_key = Some(ModulusSwitchNoiseReductionKey::new(
        pbs128_params.modulus_switch_noise_reduction_params.unwrap(),
        &cks.small_lwe_secret_key(),
        &mut engine,
        block_params.ciphertext_modulus(),
        block_params.lwe_noise_distribution(),
    ));

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        assert_eq!(
            input_lwe_secret_key_as_u128.lwe_dimension(),
            pbs128_params.input_lwe_dimension
        );

        let std_bootstrapping_key =
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _, _>(
                &input_lwe_secret_key_as_u128,
                &output_pbs_128_glwe_secret_key,
                pbs128_params.decomp_base_log,
                pbs128_params.decomp_level_count,
                pbs128_params.glwe_noise_distribution,
                pbs128_params.ciphertext_modulus,
                &mut engine.encryption_generator,
            );

        let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fbsk);

        fbsk
    };

    let compression_private_key;
    let decompression_key;

    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);
            decompression_key = cks
                .new_compression_decompression_keys(&compression_private_key)
                .1;

            (
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => {
            let (_key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
                AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
                    standard_atomic_pattern_server_key
                        .key_switching_key
                        .as_view(),
                    &standard_atomic_pattern_server_key.bootstrapping_key,
                ),
                AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
                AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
            };
            (&cks.small_lwe_secret_key(), bootstrapping_key)
        }
    };

    // We get out under the big key of the compute params, so we can check this noise distribution
    let expected_variance_after_input_br = match block_params.glwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => pbs_variance_132_bits_security_gaussian(
            input_br_key.input_lwe_dimension(),
            input_br_key.glwe_size().to_glwe_dimension(),
            input_br_key.polynomial_size(),
            input_br_key.decomposition_base_log(),
            input_br_key.decomposition_level_count(),
            compute_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_variance_132_bits_security_tuniform(
            input_br_key.input_lwe_dimension(),
            input_br_key.glwe_size().to_glwe_dimension(),
            input_br_key.polynomial_size(),
            input_br_key.decomposition_base_log(),
            input_br_key.decomposition_level_count(),
            compute_modulus_as_f64,
        ),
    };

    let scalar_for_multiplication = block_params.max_noise_level().get();
    let expected_variance_after_multiplication =
        scalar_multiplication_variance(expected_variance_after_input_br, scalar_for_multiplication);

    let (key_switching_key, _bootstrapping_key) = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
            standard_atomic_pattern_server_key
                .key_switching_key
                .as_view(),
            &standard_atomic_pattern_server_key.bootstrapping_key,
        ),
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
        AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
    };

    let compute_ks_input_lwe_dimension = key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = key_switching_key.decomposition_level_count();

    let keyswitch_additive_variance = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(_) => keyswitch_additive_variance_132_bits_security_gaussian(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => keyswitch_additive_variance_132_bits_security_tuniform(
            compute_ks_input_lwe_dimension,
            compute_ks_output_lwe_dimension,
            compute_ks_decomp_base_log,
            compute_ks_decomp_level_count,
            compute_modulus_as_f64,
        ),
    };

    let expected_variance_after_ks =
        Variance(expected_variance_after_multiplication.0 + keyswitch_additive_variance.0);

    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_128_input_modulus = 1u64 << br_128_input_modulus_log.0;

    let drift_mitigation_additive_var = match block_params.lwe_noise_distribution() {
        DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
        DynamicDistribution::TUniform(tuniform) => tuniform.variance(compute_modulus_as_f64),
    };

    let expected_variance_after_drift_mitigation =
        Variance(expected_variance_after_ks.0 + drift_mitigation_additive_var.0);

    let ms_additive_variance = generalized_modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        compute_modulus_as_f64,
        br_128_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_drift_mitigation.0 + ms_additive_variance.0);

    let expected_variance_after_pbs_128 = match pbs128_params.glwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => pbs_128_variance_132_bits_security_gaussian(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_size().to_glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomposition_base_log(),
            pbs_128_key.decomposition_level_count(),
            pbs128_params.mantissa_size,
            pbs128_output_modulus_as_f64,
        ),
        DynamicDistribution::TUniform(_) => pbs_128_variance_132_bits_security_tuniform(
            pbs_128_key.input_lwe_dimension(),
            pbs_128_key.glwe_size().to_glwe_dimension(),
            pbs_128_key.polynomial_size(),
            pbs_128_key.decomposition_base_log(),
            pbs_128_key.decomposition_level_count(),
            pbs128_params.mantissa_size,
            pbs128_output_modulus_as_f64,
        ),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_before_drift_mitigation = vec![];
    let mut noise_samples_before_ms_of_pbs_128 = vec![];
    let mut noise_samples_before_pbs_128 = vec![];
    let mut noise_samples_after_pbs_128 = vec![];

    let sample_count_per_msg = 1000;

    for msg in 0..cleartext_modulus {
        let (
            (
                current_noise_samples_before_drift_mitigation,
                current_noise_samples_before_ms_of_pbs_128,
            ),
            (current_noise_samples_before_pbs_128, current_noise_samples_after_pbs_128),
        ): ((Vec<_>, Vec<_>), (Vec<_>, Vec<_>)) = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                br_to_squash_pbs_128_noise_helper(
                    input_br_params,
                    block_params,
                    pbs128_params,
                    encryption_key,
                    input_br_key,
                    &cks,
                    &sks,
                    before_pbs_128_ms_noise_reduction_key.as_ref(),
                    &pbs_128_key,
                    &output_pbs_128_glwe_secret_key.as_view(),
                    msg,
                    scalar_for_multiplication.try_into().unwrap(),
                )
            })
            .unzip();

        noise_samples_before_drift_mitigation.extend(
            current_noise_samples_before_drift_mitigation
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_before_ms_of_pbs_128.extend(
            current_noise_samples_before_ms_of_pbs_128
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_before_pbs_128.extend(
            current_noise_samples_before_pbs_128
                .into_iter()
                .map(|x| x.value),
        );

        noise_samples_after_pbs_128.extend(
            current_noise_samples_after_pbs_128
                .into_iter()
                .map(|x| x.value),
        );
    }

    println!();

    let normality_check_before_drift_mitigation = normality_test_f64(
        &noise_samples_before_drift_mitigation
            [..5000.min(noise_samples_before_drift_mitigation.len())],
        0.01,
    );

    if normality_check_before_drift_mitigation.null_hypothesis_is_valid {
        println!("Normality check before drift mitigation is OK\n");
    } else {
        println!("Normality check before drift mitigation failed\n");
    }

    let normality_check_before_ms = normality_test_f64(
        &noise_samples_before_ms_of_pbs_128[..5000.min(noise_samples_before_ms_of_pbs_128.len())],
        0.01,
    );

    if normality_check_before_ms.null_hypothesis_is_valid {
        println!("Normality check before MS is OK\n");
    } else {
        println!("Normality check before MS failed\n");
    }

    let before_drift_mitigation_is_ok = mean_and_variance_check(
        &noise_samples_before_drift_mitigation,
        "before_drift_mitigation",
        0.0,
        expected_variance_after_ks,
        block_params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        compute_modulus_as_f64,
    );

    let before_ms_of_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_before_ms_of_pbs_128,
        "before_ms_of_pbs_128",
        0.0,
        expected_variance_after_drift_mitigation,
        block_params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        compute_modulus_as_f64,
    );

    let before_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_before_pbs_128,
        "before_pbs_128",
        0.0,
        expected_variance_after_ms,
        block_params.lwe_noise_distribution(),
        cks.small_lwe_secret_key().lwe_dimension(),
        compute_modulus_as_f64,
    );

    let after_pbs_128_is_ok = mean_and_variance_check(
        &noise_samples_after_pbs_128,
        "after_pbs_128",
        0.0,
        expected_variance_after_pbs_128,
        pbs128_params.glwe_noise_distribution,
        output_pbs_128_glwe_secret_key
            .as_lwe_secret_key()
            .lwe_dimension(),
        pbs128_output_modulus_as_f64,
    );

    assert!(
        before_drift_mitigation_is_ok
            && before_ms_of_pbs_128_is_ok
            && before_pbs_128_is_ok
            && after_pbs_128_is_ok
            && normality_check_before_drift_mitigation.null_hypothesis_is_valid
            && normality_check_before_ms.null_hypothesis_is_valid
    );

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

#[test]
fn test_noise_check_shortint_compute_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Compute,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PBS128_PARAMS,
    )
}

#[ignore = "We will not perform the PBS 128 after decompression"]
#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Decompression {
            params: V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        },
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PBS128_PARAMS,
    )
}

fn noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
    input_br_params: PBS128InputBRParams,
    mut block_params: ClassicPBSParameters,
    pbs128_params: PBS128Parameters,
) {
    assert_eq!(
        block_params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        block_params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * block_params.carry_modulus.0 * block_params.message_modulus.0).ilog2();
    block_params.carry_modulus.0 = 1 << 4;

    let new_precision_with_padding =
        (2 * block_params.message_modulus.0 * block_params.carry_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(block_params.log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", block_params.log2_p_fail);

    let expected_pfail_before_pbs_128 = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    let expected_pfail_before_pbs_128_log2 = expected_pfail_before_pbs_128.log2();

    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");
    println!("expected_pfail_before_pbs_128_log2={expected_pfail_before_pbs_128_log2}");

    let (runs_for_expected_fails, expected_fails_before_pbs_128, total_sample_count) =
        if should_run_long_pfail_tests() {
            let total_runs = 1_000_000;
            let expected_fails = (total_runs as f64 * expected_pfail_before_pbs_128).round() as u32;
            (total_runs, expected_fails, total_runs)
        } else {
            let expected_fails_before_pbs_128 = 200;
            let samples_per_run = 1;

            let runs_for_expected_fails = (expected_fails_before_pbs_128 as f64
                / (expected_pfail_before_pbs_128 * samples_per_run as f64))
                .round() as usize;

            let total_sample_count = runs_for_expected_fails * samples_per_run;
            (
                runs_for_expected_fails,
                expected_fails_before_pbs_128,
                total_sample_count,
            )
        };

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

    assert!(block_params.modulus_switch_noise_reduction_params.is_some());
    let block_params: ShortintParameterSet = block_params.into();
    assert!(
        matches!(
            block_params.encryption_key_choice(),
            EncryptionKeyChoice::Big
        ),
        "This test only supports encryption under the big key for now."
    );
    assert!(
        block_params
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This test only supports encrytpion with power of 2 moduli for now."
    );

    let cks = ClientKey::new(block_params);
    let sks = ServerKey::new(&cks);
    let output_pbs_128_glwe_secret_key;

    let mut engine = ShortintEngine::new();

    let before_pbs_128_ms_noise_reduction_key = Some(ModulusSwitchNoiseReductionKey::new(
        pbs128_params.modulus_switch_noise_reduction_params.unwrap(),
        &cks.small_lwe_secret_key(),
        &mut engine,
        block_params.ciphertext_modulus(),
        block_params.lwe_noise_distribution(),
    ));

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        output_pbs_128_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key::<u128, _>(
            pbs128_params.glwe_dimension,
            pbs128_params.polynomial_size,
            &mut engine.secret_generator,
        );

        assert_eq!(
            input_lwe_secret_key_as_u128.lwe_dimension(),
            pbs128_params.input_lwe_dimension
        );

        let std_bootstrapping_key =
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _, _>(
                &input_lwe_secret_key_as_u128,
                &output_pbs_128_glwe_secret_key,
                pbs128_params.decomp_base_log,
                pbs128_params.decomp_level_count,
                pbs128_params.glwe_noise_distribution,
                pbs128_params.ciphertext_modulus,
                &mut engine.encryption_generator,
            );

        let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );

        convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bootstrapping_key, &mut fbsk);

        fbsk
    };

    let compression_private_key;
    let decompression_key;

    let (encryption_key, input_br_key) = match input_br_params {
        PBS128InputBRParams::Decompression { params } => {
            compression_private_key = cks.new_compression_private_key(params);
            decompression_key = cks
                .new_compression_decompression_keys(&compression_private_key)
                .1;

            (
                &compression_private_key
                    .post_packing_ks_key
                    .as_lwe_secret_key(),
                &decompression_key.blind_rotate_key,
            )
        }
        PBS128InputBRParams::Compute => {
            let (_key_switching_key, bootstrapping_key) = match &sks.atomic_pattern {
                AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => (
                    standard_atomic_pattern_server_key
                        .key_switching_key
                        .as_view(),
                    &standard_atomic_pattern_server_key.bootstrapping_key,
                ),
                AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => todo!(),
                AtomicPatternServerKey::Dynamic(_dynamic_atomic_pattern) => todo!(),
            };
            (&cks.small_lwe_secret_key(), bootstrapping_key)
        }
    };

    let scalar_for_multiplication = block_params.max_noise_level().get();

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let (measured_fails_before_pbs_128, _measured_fails_after_pbs_128): (Vec<_>, Vec<_>) = (0
        ..runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;

            br_to_squash_pbs_128_pfail_helper(
                input_br_params,
                block_params,
                pbs128_params,
                encryption_key,
                input_br_key,
                &cks,
                &sks,
                before_pbs_128_ms_noise_reduction_key.as_ref(),
                &pbs_128_key,
                &output_pbs_128_glwe_secret_key.as_view(),
                msg,
                scalar_for_multiplication.try_into().unwrap(),
            )
        })
        .unzip();

    let sample_count = measured_fails_before_pbs_128.len();
    let measured_fails_before_pbs_128: f64 = measured_fails_before_pbs_128.into_iter().sum();
    let measured_pfail_before_pbs_128 = measured_fails_before_pbs_128 / (sample_count as f64);

    println!("measured_fails_before_pbs_128={measured_fails_before_pbs_128}");
    println!("measured_pfail_before_pbs_128={measured_pfail_before_pbs_128}");
    println!("expected_fails_before_pbs_128={expected_fails_before_pbs_128}");
    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");

    let equivalent_measured_pfail_before_pbs_128 = equivalent_pfail_gaussian_noise(
        new_precision_with_padding,
        measured_pfail_before_pbs_128,
        original_precision_with_padding,
    );

    println!("equivalent_measured_pfail_before_pbs_128={equivalent_measured_pfail_before_pbs_128}");
    println!("original_expected_pfail_before_pbs_128  ={original_pfail}");
    println!(
        "equivalent_measured_pfail_before_pbs_128_log2={}",
        equivalent_measured_pfail_before_pbs_128.log2()
    );
    println!(
        "original_expected_pfail_before_pbs_128_log2  ={}",
        original_pfail.log2()
    );

    if measured_fails_before_pbs_128 > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_before_pbs_128,
            0.99,
        );

        let pfail_lower_bound = pfail_confidence_interval.lower_bound();
        let pfail_upper_bound = pfail_confidence_interval.upper_bound();
        println!("pfail_lower_bound={pfail_lower_bound}");
        println!("pfail_upper_bound={pfail_upper_bound}");

        let equivalent_pfail_lower_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_lower_bound,
            original_precision_with_padding,
        );
        let equivalent_pfail_upper_bound = equivalent_pfail_gaussian_noise(
            new_precision_with_padding,
            pfail_upper_bound,
            original_precision_with_padding,
        );

        println!("equivalent_pfail_lower_bound={equivalent_pfail_lower_bound}");
        println!("equivalent_pfail_upper_bound={equivalent_pfail_upper_bound}");
        println!(
            "equivalent_pfail_lower_bound_log2={}",
            equivalent_pfail_lower_bound.log2()
        );
        println!(
            "equivalent_pfail_upper_bound_log2={}",
            equivalent_pfail_upper_bound.log2()
        );

        if measured_pfail_before_pbs_128 <= expected_pfail_before_pbs_128 {
            if !pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128) {
                println!(
                    "\n==========\n\
                    WARNING: measured pfail is smaller than expected pfail \
                    and out of the confidence interval\n\
                    the optimizer might be pessimistic when generating parameters.\n\
                    ==========\n"
                );
            }
        } else {
            assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail_before_pbs_128));
        }
    } else {
        println!(
            "\n==========\n\
            WARNING: measured pfail is 0, it is either a bug or \
            it is way smaller than the expected pfail\n\
            the optimizer might be pessimistic when generating parameters.\n\
            ==========\n"
        );
    }
}

#[test]
fn test_noise_check_shortint_compute_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Compute,
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PBS128_PARAMS,
    )
}

#[ignore = "We will not perform the PBS 128 after decompression"]
#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Decompression {
            params: V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        },
        V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PBS128_PARAMS,
    )
}
