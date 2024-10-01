use super::*;
use crate::core_crypto::commons::noise_formulas::lwe_keyswitch::keyswitch_additive_variance_132_bits_security_gaussian;
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::commons::test_tools::{torus_modular_diff, variance};
use rayon::prelude::*;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 1000;

fn lwe_encrypt_ks_decrypt_noise_distribution_custom_mod<Scalar: UnsignedTorus + CastInto<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    let input_lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    let output_lwe_dimension = lwe_dimension;

    let modulus_as_f64 = if ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(Scalar::BITS as i32)
    } else {
        ciphertext_modulus.get_custom_modulus() as f64
    };

    let encryption_variance = glwe_noise_distribution.gaussian_std_dev().get_variance();
    let expected_variance = Variance(
        encryption_variance.0
            + keyswitch_additive_variance_132_bits_security_gaussian(
                input_lwe_dimension,
                output_lwe_dimension,
                ks_decomp_base_log,
                ks_decomp_level_count,
                modulus_as_f64,
            )
            .0,
    );

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let big_lwe_sk = glwe_sk.into_lwe_secret_key();

    let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk,
        &lwe_sk,
        ks_decomp_base_log,
        ks_decomp_level_count,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &ksk_big_to_small,
        ciphertext_modulus
    ));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        let current_run_samples: Vec<_> = (0..NB_TESTS)
            .into_par_iter()
            .map(|_| {
                let mut rsc = TestResources::new();

                let plaintext = Plaintext(msg * delta);

                let ct = allocate_and_encrypt_new_lwe_ciphertext(
                    &big_lwe_sk,
                    plaintext,
                    glwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.encryption_random_generator,
                );

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus
                ));

                let mut output_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    lwe_sk.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);

                assert!(check_encrypted_content_respects_mod(
                    &output_ct,
                    ciphertext_modulus
                ));

                let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(msg, decoded);

                torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus)
            })
            .collect();

        noise_samples.extend(current_run_samples);
    }

    let measured_variance = variance(&noise_samples);

    let minimal_variance = minimal_lwe_variance_for_132_bits_security_gaussian(
        ksk_big_to_small.output_key_lwe_dimension(),
        if ciphertext_modulus.is_native_modulus() {
            2.0f64.powi(Scalar::BITS as i32)
        } else {
            ciphertext_modulus.get_custom_modulus() as f64
        },
    );

    // Have a log even if it's a test to have a trace in no capture mode to eyeball variances
    println!("measured_variance={measured_variance:?}");
    println!("expected_variance={expected_variance:?}");
    println!("minimal_variance={minimal_variance:?}");

    if measured_variance.0 < expected_variance.0 {
        // We are in the clear as long as we have at least the noise for security
        assert!(
            measured_variance.0 >= minimal_variance.0,
            "Found insecure variance after keyswitch\n\
            measure_variance={measured_variance:?}\n\
            minimal_variance={minimal_variance:?}"
        );
    } else {
        // Check we are not too far from the expected variance if we are bigger
        let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
        let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;

        assert!(
            var_abs_diff < tolerance_threshold,
            "Absolute difference for variance: {var_abs_diff}, \
            tolerance threshold: {tolerance_threshold}, \
            got variance: {measured_variance:?}, \
            expected variance: {expected_variance:?}"
        );
    }
}

create_parameterized_test!(lwe_encrypt_ks_decrypt_noise_distribution_custom_mod {
    NOISE_TEST_PARAMS_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN,
});
