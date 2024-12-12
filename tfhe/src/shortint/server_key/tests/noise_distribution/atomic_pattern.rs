use super::{scalar_multiplication_variance, should_use_one_key_per_sample};
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::glwe_secret_key_generation::allocate_and_generate_new_binary_glwe_secret_key;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::lwe_keyswitch::keyswitch_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_linear_algebra::lwe_ciphertext_plaintext_sub_assign;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128::programmable_bootstrap_f128_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::algorithms::test::noise_distribution::lwe_encryption_noise::lwe_compact_public_key_encryption_expected_variance;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
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
    minimal_lwe_variance_for_132_bits_security_gaussian,
    minimal_lwe_variance_for_132_bits_security_tuniform, variance_to_tuniform_bound_log2,
};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus as CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    GlweDimension, LweDimension, MonomialDegree, PolynomialSize,
};
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, clopper_pearson_exact_confidence_interval, equivalent_pfail_gaussian_noise,
    mean_confidence_interval, torus_modular_diff, variance, variance_confidence_interval,
};
use crate::core_crypto::commons::traits::{Container, UnsignedInteger};
use crate::core_crypto::entities::{GlweSecretKey, LweCiphertext, LweSecretKey, Plaintext};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{CompressionKey, CompressionPrivateKeys, DecompressionKey};
use crate::shortint::parameters::classic::gaussian::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::compact_public_key_only::{
    CompactCiphertextListExpansionKind, CompactPublicKeyEncryptionParameters,
    ShortintCompactCiphertextListCastingMode,
};
use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::{
    PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};
use crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters;
use crate::shortint::parameters::list_compression::{
    CompressionParameters, COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DynamicDistribution,
    EncryptionKeyChoice, MessageModulus, ShortintParameterSet,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::server_key::{apply_programmable_bootstrap, ShortintBootstrappingKey};
use crate::shortint::{
    Ciphertext, ClientKey, CompactPrivateKey, CompactPublicKey, KeySwitchingKey, ServerKey,
};
use rayon::prelude::*;

fn noise_check_shortint_classic_pbs_before_pbs_after_encryption_noise(
    params: ClassicPBSParameters,
) {
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

    let input_ks_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

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

    let ms_additive_var = modulus_switch_additive_variance(
        output_ks_lwe_dimension,
        modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms = Variance(expected_variance_after_ks.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples = vec![];
    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..1000)
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
                    sks.key_switching_key.output_lwe_size(),
                    sks.key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(&sks.key_switching_key, &ct.ct, &mut after_ks_lwe);

                let mut after_ms = LweCiphertext::new(
                    0u64,
                    after_ks_lwe.lwe_size(),
                    // This will be easier to manage when decrypting, we'll put the value in the
                    // MSB
                    params.ciphertext_modulus(),
                );

                for (dst, src) in after_ms
                    .as_mut()
                    .iter_mut()
                    .zip(after_ks_lwe.as_ref().iter())
                {
                    *dst = modulus_switch(*src, br_input_modulus_log) << shift_to_map_to_native;
                }

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
                    sks.bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    sks.bootstrapping_key.input_lwe_dimension(),
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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
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

fn classic_pbs_atomic_pattern_inner_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> DecryptionAndNoiseResult {
    assert!(params.pbs_only());
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
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

    let delta = (1u64 << 63) / cleartext_modulus;
    let native_mod_plaintext = Plaintext(msg * delta);

    // We want to encrypt the ciphertext under modulus 2N but then use the native
    // modulus to simulate a noiseless mod switch as input
    let input_pbs_lwe_ct = {
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
        // Now get the noiseless mod switched encryption under the proper modulus
        // The power of 2 modulus are always encrypted in the MSBs, so this is fine
        LweCiphertext::from_container(raw_data, params.ciphertext_modulus())
    };

    let mut after_pbs_shortint_ct = sks.unchecked_create_trivial_with_lwe_size(
        0,
        sks.bootstrapping_key.output_lwe_dimension().to_lwe_size(),
    );

    let (_, buffers) = engine.get_buffers(sks);

    // Apply the PBS only
    apply_programmable_bootstrap(
        &sks.bootstrapping_key,
        &input_pbs_lwe_ct,
        &mut after_pbs_shortint_ct.ct,
        &identity_lut.acc,
        buffers,
    );

    after_pbs_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    // Remove the plaintext before the mul to avoid degree issues but sill increase the
    // noise
    lwe_ciphertext_plaintext_sub_assign(&mut after_pbs_shortint_ct.ct, native_mod_plaintext);

    sks.unchecked_scalar_mul_assign(&mut after_pbs_shortint_ct, scalar_for_multiplication);

    // Put the message back in after mul to have our msg in a noisy ct
    sks.unchecked_scalar_add_assign(&mut after_pbs_shortint_ct, msg.try_into().unwrap());

    let mut after_ks_lwe = LweCiphertext::new(
        0u64,
        sks.key_switching_key.output_lwe_size(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext(
        &sks.key_switching_key,
        &after_pbs_shortint_ct.ct,
        &mut after_ks_lwe,
    );

    let mut after_ms = LweCiphertext::new(
        0u64,
        after_ks_lwe.lwe_size(),
        // This will be easier to manage when decrypting, we'll put the value in the
        // MSB
        params.ciphertext_modulus(),
    );

    for (dst, src) in after_ms
        .as_mut()
        .iter_mut()
        .zip(after_ks_lwe.as_ref().iter())
    {
        *dst = modulus_switch(*src, br_input_modulus_log) << shift_to_map_to_native;
    }

    DecryptionAndNoiseResult::new(
        &after_ms,
        &cks.small_lwe_secret_key(),
        msg,
        delta,
        cleartext_modulus,
    )
}

fn classic_pbs_atomic_pattern_noise_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> NoiseSample {
    let decryption_and_noise_result = classic_pbs_atomic_pattern_inner_helper(
        params,
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

/// Return 1 if the decryption failed, otherwise 0, allowing to sum the results of threads to get
/// the failure rate.
fn classic_pbs_atomic_pattern_pfail_helper(
    params: ShortintParameterSet,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u8,
) -> f64 {
    let decryption_and_noise_result = classic_pbs_atomic_pattern_inner_helper(
        params,
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

fn noise_check_shortint_classic_pbs_atomic_pattern_noise(params: ClassicPBSParameters) {
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

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);

    let input_pbs_lwe_dimension = sks.bootstrapping_key.input_lwe_dimension();
    let output_glwe_dimension = sks.bootstrapping_key.glwe_size().to_glwe_dimension();
    let output_polynomial_size = sks.bootstrapping_key.polynomial_size();
    let pbs_decomp_base_log = sks.bootstrapping_key.decomposition_base_log();
    let pbs_decomp_level_count = sks.bootstrapping_key.decomposition_level_count();

    let input_ks_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let output_ks_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

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

    let ms_additive_var = modulus_switch_additive_variance(
        output_ks_lwe_dimension,
        modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms = Variance(expected_variance_after_ks.0 + ms_additive_var.0);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples = vec![];
    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..1000)
            .into_par_iter()
            .map(|_| {
                classic_pbs_atomic_pattern_noise_helper(
                    params,
                    &cks,
                    &sks,
                    msg,
                    scalar_for_multiplication.try_into().unwrap(),
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
        let noise_for_security = match params.lwe_noise_distribution() {
            DynamicDistribution::Gaussian(_) => {
                minimal_lwe_variance_for_132_bits_security_gaussian(
                    sks.bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    sks.bootstrapping_key.input_lwe_dimension(),
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

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_noise {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
});

fn noise_check_shortint_classic_pbs_atomic_pattern_pfail(mut params: ClassicPBSParameters) {
    assert_eq!(
        params.carry_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );
    assert_eq!(
        params.message_modulus.0, 4,
        "This test is only for 2_2 parameters"
    );

    // Padding bit + carry and message
    let original_precision_with_padding =
        (2 * params.carry_modulus.0 * params.message_modulus.0).ilog2();
    params.carry_modulus.0 = 1 << 4;

    let new_precision_with_padding =
        (2 * params.carry_modulus.0 * params.message_modulus.0).ilog2();

    let original_pfail = 2.0f64.powf(params.log2_p_fail);

    println!("original_pfail={original_pfail}");
    println!("original_pfail_log2={}", params.log2_p_fail);

    let expected_pfail = equivalent_pfail_gaussian_noise(
        original_precision_with_padding,
        original_pfail,
        new_precision_with_padding,
    );

    params.log2_p_fail = expected_pfail.log2();

    println!("expected_pfail={expected_pfail}");
    println!("expected_pfail_log2={}", params.log2_p_fail);

    let expected_fails = 200;

    let runs_for_expected_fails = (expected_fails as f64 / expected_pfail).round() as u32;
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

    if measured_fails > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
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
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
});

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
                    expanded_ct.pbs_order,
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
                    sks.key_switching_key.output_lwe_size(),
                    sks.key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(
                    &sks.key_switching_key,
                    &shortint_ct_after_pke_ks.ct,
                    &mut lwe_keyswitchted,
                );

                // Return the result
                lwe_keyswitchted
            }
            EncryptionKeyChoice::Small => after_ks_lwe_ct,
        }
    };

    let mut after_ms = LweCiphertext::new(
        0u64,
        before_ms.lwe_size(),
        // This will be easier to manage when decrypting, we'll put the value in the
        // MSB
        before_ms.ciphertext_modulus(),
    );

    for (dst, src) in after_ms.as_mut().iter_mut().zip(before_ms.as_ref().iter()) {
        *dst = modulus_switch(*src, br_input_modulus_log) << shift_to_map_to_native;
    }

    DecryptionAndNoiseResult::new(
        &after_ms,
        &cks.small_lwe_secret_key(),
        msg,
        delta,
        cleartext_modulus,
    )
}

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

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    let compute_pbs_input_lwe_dimension = sks.bootstrapping_key.input_lwe_dimension();

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

    let expected_variance_before_ms = {
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

    let ms_additive_variance = modulus_switch_additive_variance(
        compute_pbs_input_lwe_dimension,
        modulus_as_f64,
        br_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_before_ms.0 + ms_additive_variance.0);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples = vec![];
    for msg in 0..cleartext_modulus {
        let current_noise_samples: Vec<_> = (0..1000)
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
                    sks.bootstrapping_key.input_lwe_dimension(),
                    modulus_as_f64,
                )
            }
            DynamicDistribution::TUniform(_) => {
                minimal_lwe_variance_for_132_bits_security_tuniform(
                    sks.bootstrapping_key.input_lwe_dimension(),
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
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_noise() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_noise(
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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

    let expected_fails = 200;

    let runs_for_expected_fails = (expected_fails as f64 / expected_pfail).round() as u32;
    println!("runs_for_expected_fails={runs_for_expected_fails}");

    // Disable the auto casting in the keyswitching key to be able to measure things ourselves
    cpke_params.expansion_kind =
        CompactCiphertextListExpansionKind::NoCasting(block_params.encryption_key_choice.into());
    // Remove mutability
    let cpke_params = cpke_params;

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
                scalar_for_multiplication.try_into().unwrap(),
            )
        })
        .sum();

    let measured_pfail = measured_fails / (runs_for_expected_fails as f64);

    println!("measured_fails={measured_fails}");
    println!("expected_fails={expected_fails}");
    println!("measured_pfail={measured_pfail}");
    println!("expected_pfail={expected_pfail}");

    if measured_fails > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            runs_for_expected_fails as f64,
            measured_fails,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
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
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    )
}

#[test]
fn test_noise_check_shortint_pke_encrypt_ks_to_big_pfail() {
    noise_check_shortint_pke_encrypt_ks_to_compute_params_pfail(
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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
    };

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

    let compute_br_input_modulus_log = sks
        .bootstrapping_key
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

            let (_, buffers) = engine.get_buffers(&sks);

            // Apply the PBS to get out noisy and under the proper encryption key
            apply_programmable_bootstrap(
                &sks.bootstrapping_key,
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
                sks.key_switching_key.output_lwe_size(),
                sks.key_switching_key.ciphertext_modulus(),
            );

            keyswitch_lwe_ciphertext(&sks.key_switching_key, &decompressed.ct, &mut after_ks_lwe);

            for val in after_ks_lwe.as_mut() {
                *val = modulus_switch(*val, compute_br_input_modulus_log) << shift_to_map_to_native;
            }

            let after_ms_lwe = after_ks_lwe;
            after_ms_lwe
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

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

    let compute_pbs_input_lwe_dimension = sks.bootstrapping_key.input_lwe_dimension();
    let compute_pbs_output_glwe_dimension = sks.bootstrapping_key.glwe_size().to_glwe_dimension();
    let compute_pbs_output_polynomial_size = sks.bootstrapping_key.polynomial_size();
    let compute_pbs_decomp_base_log = sks.bootstrapping_key.decomposition_base_log();
    let compute_pbs_decomp_level_count = sks.bootstrapping_key.decomposition_level_count();

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

    let ap_ms_additive_variance = modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        modulus_as_f64,
        ap_br_input_modulus as f64,
    );

    let expected_variance_after_ap_ms =
        Variance(expected_variance_after_ap_ks.0 + ap_ms_additive_variance.0);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let mut noise_samples_after_compression = vec![];
    let mut noise_samples_after_ap = vec![];
    let number_of_runs = 1000usize.div_ceil(compression_key.lwe_per_glwe.0);
    // let number_of_runs = 1000;
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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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

    let expected_fails_after_ap = 200;
    let samples_per_run = compression_params.lwe_per_glwe.0;

    let runs_for_expected_fails = (expected_fails_after_ap as f64
        / (expected_pfail_after_ap * samples_per_run as f64))
        .round() as usize;

    let total_sample_count = runs_for_expected_fails * samples_per_run;

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

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

    if measured_fails_after_ap > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_after_ap,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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

    let run_count = 500;
    let total_sample_count = run_count * samples_per_run;

    println!("run_count={run_count}");
    println!("total_sample_count={total_sample_count}");

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
    let equivalent_pfail_ms_storage = equivalent_pfail_gaussian_noise(
        precision_used_during_compression,
        measured_pfail_after_ms_storage,
        1 + original_compression_cleartext_modulus.ilog2(),
    );

    let equivalent_pfail_ms_storage_log2 = equivalent_pfail_ms_storage.log2();

    println!("equivalent_pfail_ms_storage={equivalent_pfail_ms_storage}");
    println!("equivalent_pfail_ms_storage_log2={equivalent_pfail_ms_storage_log2}");

    assert!(equivalent_pfail_ms_storage <= 2.0f64.powi(-64));

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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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

        println!(
            "PASS: measured_variance_{suffix} is smaller than expected variance, \
            but confidence interval does not contain the expected variance"
        );

        if !variance_ci.variance_is_in_interval(expected_variance) {
            println!(
                "\n==========\n\
                Warning: noise formula might be over estimating the noise.\n\
                ==========\n"
            );
        }

        measured_variance >= noise_for_security
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
    // There was a doubt on the mantissa size, several experiments were conducted
    mantissa_size: f64,
    ciphertext_modulus: CoreCiphertextModulus<u128>,
}

// Mantissa 106
// hat_N, hat_k, hat_l_bs, hat_b_bs
// 2048,      2,        3, 4294967296
// hat_b_bs_log2 = 32

// Mantissa 100
// hat_N, hat_k, hat_l_bs, hat_b_bs
// 2048,      2,        3, 67108864
// hat_b_bs_log2 = 26

// Mantissa 104
// hat_N, hat_k, hat_l_bs, hat_b_bs
// 2048,      2,        3, 536870912
// hat_b_bs_log2 = 29
const PBS128_PARAMS: PBS128Parameters = PBS128Parameters {
    input_lwe_dimension: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64.lwe_dimension,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(31),
    decomp_base_log: DecompositionBaseLog(29),
    decomp_level_count: DecompositionLevelCount(3),
    mantissa_size: 104f64,
    // 2^128
    ciphertext_modulus: CoreCiphertextModulus::new_native(),
};

#[test]
fn test_noise_check_pbs_128_secure_noise() {
    let params = PBS128_PARAMS;

    let modulus_as_f64 = if params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(128)
    } else {
        params.ciphertext_modulus.get_custom_modulus() as f64
    };

    let output_lwe_dimension = params
        .glwe_dimension
        .to_equivalent_lwe_dimension(params.polynomial_size);

    let secure_tuniform_variance =
        minimal_lwe_variance_for_132_bits_security_tuniform(output_lwe_dimension, modulus_as_f64);
    let tuniform_bound = variance_to_tuniform_bound_log2(secure_tuniform_variance, modulus_as_f64);

    match params.glwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => panic!("Only TUniform is checked here"),
        DynamicDistribution::TUniform(tuniform) => {
            assert_eq!(tuniform.bound_log2(), tuniform_bound)
        }
    }
}

fn br_to_squash_pbs_128_inner_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (DecryptionAndNoiseResult, DecryptionAndNoiseResult) {
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
    let thread_pbs_128_key;
    let thread_output_pbs_128_glwe_secret_key;
    let (cks, sks, encryption_key, input_br_key, pbs_128_key, output_pbs_128_glwe_secret_key) =
        if should_use_one_key_per_sample() {
            thread_cks = engine.new_client_key(block_params);
            thread_sks = engine.new_server_key(&thread_cks);

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
                PBS128InputBRParams::Compute => (
                    thread_cks.small_lwe_secret_key(),
                    &thread_sks.bootstrapping_key,
                ),
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
                    par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
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

                convert_standard_lwe_bootstrap_key_to_fourier_128(
                    &std_bootstrapping_key,
                    &mut fbsk,
                );

                fbsk
            };

            (
                &thread_cks,
                &thread_sks,
                &thread_encryption_key,
                thread_input_br_key,
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
                single_pbs_128_key,
                single_output_pbs_128_glwe_secret_key,
            )
        };

    let identity_lut = sks.generate_lookup_table(|x| x);

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let br_input_modulus_log = input_br_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let shift_to_map_to_native = u64::BITS - br_input_modulus_log.0 as u32;

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
        0,
        input_br_key.output_lwe_dimension().to_lwe_size(),
    );

    let (_, buffers) = engine.get_buffers(sks);

    // Apply the PBS only
    apply_programmable_bootstrap(
        &input_br_key,
        &input_pbs_lwe_ct,
        &mut after_pbs_shortint_ct.ct,
        &identity_lut.acc,
        buffers,
    );

    after_pbs_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, sks.max_noise_level);

    let mut after_ks_lwe = LweCiphertext::new(
        0u64,
        sks.key_switching_key.output_lwe_size(),
        sks.key_switching_key.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext(
        &sks.key_switching_key,
        &after_pbs_shortint_ct.ct,
        &mut after_ks_lwe,
    );

    let mut after_ms = LweCiphertext::new(
        0u64,
        after_ks_lwe.lwe_size(),
        // This will be easier to manage when decrypting, we'll put the value in the
        // MSB
        block_params.ciphertext_modulus(),
    );

    for (dst, src) in after_ms
        .as_mut()
        .iter_mut()
        .zip(after_ks_lwe.as_ref().iter())
    {
        *dst = modulus_switch(*src, br_input_modulus_log) << shift_to_map_to_native;
    }

    let mut input_pbs_128 = LweCiphertext::new(
        0u128,
        pbs_128_key.input_lwe_dimension().to_lwe_size(),
        pbs128_params.ciphertext_modulus,
    );

    assert_eq!(input_pbs_128.lwe_size(), after_ks_lwe.lwe_size());

    // Map the u64 to u128 because the pbs 128 currently does not support different input and scalar
    // types
    for (dst, src) in input_pbs_128
        .as_mut()
        .iter_mut()
        .zip(after_ks_lwe.as_ref().iter())
    {
        *dst = (*src as u128) << 64;
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
        &pbs_128_key,
    );

    (
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

fn br_to_squash_pbs_128_noise_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (NoiseSample, NoiseSample) {
    let (decryption_and_noise_result_before_pbs_128, decryption_and_noise_result_after_pbs_128) =
        br_to_squash_pbs_128_inner_helper(
            input_br_params,
            block_params,
            pbs128_params,
            single_encryption_key,
            single_input_br_key,
            single_cks,
            single_sks,
            single_pbs_128_key,
            single_output_pbs_128_glwe_secret_key,
            msg,
        );

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
    )
}

fn br_to_squash_pbs_128_pfail_helper(
    input_br_params: PBS128InputBRParams,
    block_params: ShortintParameterSet,
    pbs128_params: PBS128Parameters,
    single_encryption_key: &LweSecretKey<&[u64]>,
    single_input_br_key: &ShortintBootstrappingKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_pbs_128_key: &Fourier128LweBootstrapKeyOwned,
    single_output_pbs_128_glwe_secret_key: &GlweSecretKey<&[u128]>,
    msg: u64,
) -> (f64, f64) {
    let (decryption_and_noise_result_before_pbs_128, decryption_and_noise_result_after_pbs_128) =
        br_to_squash_pbs_128_inner_helper(
            input_br_params,
            block_params,
            pbs128_params,
            single_encryption_key,
            single_input_br_key,
            single_cks,
            single_sks,
            single_pbs_128_key,
            single_output_pbs_128_glwe_secret_key,
            msg,
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

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

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
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
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
        PBS128InputBRParams::Compute => (&cks.small_lwe_secret_key(), &sks.bootstrapping_key),
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

    let compute_ks_input_lwe_dimension = sks.key_switching_key.input_key_lwe_dimension();
    let compute_ks_output_lwe_dimension = sks.key_switching_key.output_key_lwe_dimension();
    let compute_ks_decomp_base_log = sks.key_switching_key.decomposition_base_log();
    let compute_ks_decomp_level_count = sks.key_switching_key.decomposition_level_count();

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
        Variance(expected_variance_after_input_br.0 + keyswitch_additive_variance.0);

    let br_128_input_modulus_log = pbs_128_key
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();
    let br_128_input_modulus = 1u64 << br_128_input_modulus_log.0;

    let ms_additive_variance = modulus_switch_additive_variance(
        compute_ks_output_lwe_dimension,
        compute_modulus_as_f64,
        br_128_input_modulus as f64,
    );

    let expected_variance_after_ms =
        Variance(expected_variance_after_ks.0 + ms_additive_variance.0);

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
    let mut noise_samples_before_pbs_128 = vec![];
    let mut noise_samples_after_pbs_128 = vec![];
    for msg in 0..cleartext_modulus {
        let (current_noise_samples_before_pbs_128, current_noise_samples_after_pbs_128): (
            Vec<_>,
            Vec<_>,
        ) = (0..1000)
            .into_par_iter()
            .map(|_| {
                br_to_squash_pbs_128_noise_helper(
                    input_br_params,
                    block_params,
                    pbs128_params,
                    &encryption_key,
                    &input_br_key,
                    &cks,
                    &sks,
                    &pbs_128_key,
                    &output_pbs_128_glwe_secret_key.as_view(),
                    msg,
                )
            })
            .unzip();

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

    assert!(before_pbs_128_is_ok && after_pbs_128_is_ok);

    // Normality check of heavily discretized gaussian does not seem to work
    // let normality_check = normality_test_f64(&noise_samples[..5000.min(noise_samples.len())],
    // 0.05); assert!(normality_check.null_hypothesis_is_valid);
}

#[test]
fn test_noise_check_shortint_compute_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Compute,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_noise_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_noise(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
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

    let expected_fails_before_pbs_128 = 200;
    let samples_per_run = 1;

    let runs_for_expected_fails = (expected_fails_before_pbs_128 as f64
        / (expected_pfail_before_pbs_128 * samples_per_run as f64))
        .round() as usize;

    let total_sample_count = runs_for_expected_fails * samples_per_run;

    println!("runs_for_expected_fails={runs_for_expected_fails}");
    println!("total_sample_count={total_sample_count}");

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

    let pbs_128_key = {
        let input_lwe_secret_key_as_u128 = LweSecretKey::from_container(
            cks.small_lwe_secret_key()
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let mut engine = ShortintEngine::new();

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
            par_allocate_and_generate_new_lwe_bootstrap_key::<u128, _, _, _, _>(
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
        PBS128InputBRParams::Compute => (&cks.small_lwe_secret_key(), &sks.bootstrapping_key),
    };

    let cleartext_modulus = block_params.message_modulus().0 * block_params.carry_modulus().0;
    let (measured_fails_before_pbs_128, _measured_fails_after_pbs_128): (Vec<_>, Vec<_>) = (0
        ..1000)
        .into_par_iter()
        .map(|_| {
            let msg: u64 = rand::random::<u64>() % cleartext_modulus;

            br_to_squash_pbs_128_pfail_helper(
                input_br_params,
                block_params,
                pbs128_params,
                &encryption_key,
                &input_br_key,
                &cks,
                &sks,
                &pbs_128_key,
                &output_pbs_128_glwe_secret_key.as_view(),
                msg,
            )
        })
        .unzip();

    let measured_fails_before_pbs_128: f64 = measured_fails_before_pbs_128.into_iter().sum();
    let measured_pfail_before_pbs_128 = measured_fails_before_pbs_128 / (total_sample_count as f64);

    println!("measured_fails_before_pbs_128={measured_fails_before_pbs_128}");
    println!("measured_pfail_before_pbs_128={measured_pfail_before_pbs_128}");
    println!("expected_fails_before_pbs_128={expected_fails_before_pbs_128}");
    println!("expected_pfail_before_pbs_128={expected_pfail_before_pbs_128}");

    if measured_fails_before_pbs_128 > 0.0 {
        let pfail_confidence_interval = clopper_pearson_exact_confidence_interval(
            total_sample_count as f64,
            measured_fails_before_pbs_128,
            0.99,
        );

        println!(
            "pfail_lower_bound={}",
            pfail_confidence_interval.lower_bound()
        );
        println!(
            "pfail_upper_bound={}",
            pfail_confidence_interval.upper_bound()
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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}

#[test]
fn test_noise_check_shortint_decompression_br_to_squash_pbs_128_atomic_pattern_pfail_tuniform() {
    noise_check_shortint_br_to_squash_pbs_128_atomic_pattern_pfail(
        PBS128InputBRParams::Decompression {
            params: COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        },
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PBS128_PARAMS,
    )
}
