use super::*;
use crate::core_crypto::commons::test_tools::{torus_modular_diff, variance};

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

fn lwe_encrypt_decrypt_noise_distribution_custom_mod<Scalar: UnsignedTorus + CastInto<usize>>(
    params: TestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let expected_variance = Variance(lwe_modular_std_dev.get_variance());

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 1000;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &lwe_sk,
                &mut ct,
                plaintext,
                lwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&ct, ciphertext_modulus));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_distance = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_distance);
        }
    }

    let measured_variance = variance(&noise_samples);

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

create_parametrized_test!(lwe_encrypt_decrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_63_U64
});

fn lwe_compact_public_key_encryption_expected_variance(
    input_noise: impl DispersionParameter,
    lwe_dimension: LweDimension,
) -> Variance {
    let input_variance = input_noise.get_variance();
    Variance(input_variance * (lwe_dimension.to_lwe_size().0 as f64))
}

#[test]
fn test_variance_increase_cpk_formula() {
    let predicted_variance = lwe_compact_public_key_encryption_expected_variance(
        StandardDev(2.0_f64.powi(39)),
        LweDimension(1024),
    );

    assert!(
        (predicted_variance.get_standard_dev().log2() - 44.000704097196405f64).abs() < f64::EPSILON
    );
}

fn lwe_compact_public_encrypt_noise_distribution_custom_mod<
    Scalar: UnsignedTorus + CastInto<usize>,
>(
    params: TestParams<Scalar>,
) {
    let lwe_dimension = LweDimension(params.polynomial_size.0);
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let expected_variance =
        lwe_compact_public_key_encryption_expected_variance(glwe_modular_std_dev, lwe_dimension);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 1000;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let pk = allocate_and_generate_new_lwe_compact_public_key(
                &lwe_sk,
                glwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext_with_compact_public_key(
                &pk,
                &mut ct,
                plaintext,
                glwe_modular_std_dev,
                glwe_modular_std_dev,
                &mut rsc.secret_random_generator,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&ct, ciphertext_modulus));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_distance = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_distance);
        }
    }

    let measured_variance = variance(&noise_samples);
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

create_parametrized_test!(lwe_compact_public_encrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});
