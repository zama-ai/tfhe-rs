use super::{scalar_multiplication_variance, should_use_one_key_per_sample};
use crate::core_crypto::algorithms::lwe_encryption::{
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
};
use crate::core_crypto::algorithms::lwe_keyswitch::keyswitch_lwe_ciphertext;
use crate::core_crypto::algorithms::lwe_linear_algebra::lwe_ciphertext_plaintext_sub_assign;
use crate::core_crypto::algorithms::test::round_decode;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::keyswitch_additive_variance_132_bits_security_gaussian;
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::pbs_variance_132_bits_security_gaussian;
use crate::core_crypto::commons::noise_formulas::modulus_switch::modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, clopper_pearseaon_exact_confidence_interval, equivalent_pfail_gaussian_noise,
    mean_confidence_interval, torus_modular_diff, variance, variance_confidence_interval,
};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::{LweCiphertext, LweSecretKey, Plaintext};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::classic::gaussian::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use crate::shortint::parameters::{
    CiphertextModulus, ClassicPBSParameters, DynamicDistribution, EncryptionKeyChoice,
    ShortintParameterSet,
};
use crate::shortint::server_key::apply_programmable_bootstrap;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::{ClientKey, ServerKey};
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
        DynamicDistribution::TUniform(_tuniform) => {
            todo!("This test does not yet support TUniform noise distribution.")
        }
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
        DynamicDistribution::TUniform(_) => {
            todo!("There is no keyswitch noise formula for TUniform currently")
        }
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

                let decoded = round_decode(decrypted, delta) % cleartext_modulus;
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
        let noise_for_security = minimal_lwe_variance_for_132_bits_security_gaussian(
            sks.bootstrapping_key.input_lwe_dimension(),
            modulus_as_f64,
        );

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
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
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
    fn new<CtCont, KeyCont>(
        ct: &LweCiphertext<CtCont>,
        secret_key: &LweSecretKey<KeyCont>,
        expected_msg: u64,
        delta: u64,
        cleartext_modulus: u64,
    ) -> Self
    where
        CtCont: Container<Element = u64>,
        KeyCont: Container<Element = u64>,
    {
        let decrypted_plaintext = decrypt_lwe_ciphertext(secret_key, ct).0;

        let decoded_msg = round_decode(decrypted_plaintext, delta) % cleartext_modulus;

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
        DynamicDistribution::TUniform(_) => {
            todo!("There is no pbs noise formula for TUniform currently")
        }
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
        DynamicDistribution::TUniform(_) => {
            todo!("There is no keyswitch formula for TUniform currently")
        }
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
        let noise_for_security = minimal_lwe_variance_for_132_bits_security_gaussian(
            sks.bootstrapping_key.input_lwe_dimension(),
            modulus_as_f64,
        );

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
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
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

    let pfail_confidence_interval = clopper_pearseaon_exact_confidence_interval(
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
                "WARNING: measured pfail is smaller than expected pfail \
            and out of the confidence interval\n\
            the optimizer might be pessimistic when generating parameters."
            );
        }
    } else {
        assert!(pfail_confidence_interval.mean_is_in_interval(expected_pfail));
    }
}

create_parameterized_test!(noise_check_shortint_classic_pbs_atomic_pattern_pfail {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
});
