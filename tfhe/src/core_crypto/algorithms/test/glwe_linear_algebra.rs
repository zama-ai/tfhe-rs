use super::*;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn glwe_encrypt_add_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let rhs = glwe.clone();

            glwe_ciphertext_add_assign(&mut glwe, &rhs);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == (msg + msg) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_add_assign_decrypt_custom_mod);

fn glwe_encrypt_add_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let rhs = glwe.clone();

            let mut res = glwe.clone();

            glwe_ciphertext_add(&mut res, &glwe, &rhs);

            assert!(check_encrypted_content_respects_mod(
                &res,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(res.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &res, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == (msg + msg) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_add_decrypt_custom_mod);

fn glwe_encrypt_plaintext_list_add_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_plaintext_list_add_assign(&mut glwe, &plaintext_list);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == (msg + msg) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_plaintext_list_add_assign_decrypt_custom_mod);

fn glwe_encrypt_plaintext_list_sub_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_plaintext_list_sub_assign(&mut glwe, &plaintext_list);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == Scalar::ZERO));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_plaintext_list_sub_assign_decrypt_custom_mod);

fn glwe_encrypt_plaintext_add_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);
            let plaintext_list =
                PlaintextList::new(plaintext.0, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_plaintext_add_assign(&mut glwe, plaintext);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == (msg + msg) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_plaintext_add_assign_decrypt_custom_mod);

fn glwe_encrypt_plaintext_sub_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);
            let plaintext_list =
                PlaintextList::new(plaintext.0, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_plaintext_sub_assign(&mut glwe, plaintext);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == Scalar::ZERO));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_plaintext_sub_assign_decrypt_custom_mod);

fn glwe_encrypt_opposite_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_opposite_assign(&mut glwe);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded
                .iter()
                .all(|&x| x == msg.wrapping_neg() % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_opposite_assign_decrypt_custom_mod);

fn glwe_encrypt_cleartext_mul_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;
    let cleartext = Cleartext(Scalar::TWO);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            glwe_ciphertext_cleartext_mul_assign(&mut glwe, cleartext);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded
                .iter()
                .all(|&x| x == (msg * cleartext.0) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_cleartext_mul_assign_decrypt_custom_mod);

fn glwe_encrypt_cleartext_mul_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;
    let cleartext = Cleartext(Scalar::TWO);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut res = glwe.clone();

            glwe_ciphertext_cleartext_mul(&mut res, &glwe, cleartext);

            assert!(check_encrypted_content_respects_mod(
                &res,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(res.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &res, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded
                .iter()
                .all(|&x| x == (msg * cleartext.0) % msg_modulus));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_cleartext_mul_decrypt_custom_mod);

fn glwe_encrypt_sub_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let rhs = glwe.clone();

            glwe_ciphertext_sub_assign(&mut glwe, &rhs);

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &glwe, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == Scalar::ZERO));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_sub_assign_decrypt_custom_mod);

fn glwe_encrypt_sub_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let mut glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe.polynomial_size().0));

            encrypt_glwe_ciphertext(
                &glwe_sk,
                &mut glwe,
                &plaintext_list,
                glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let rhs = glwe.clone();

            let mut res = glwe.clone();

            glwe_ciphertext_sub(&mut res, &glwe, &rhs);

            assert!(check_encrypted_content_respects_mod(
                &res,
                ciphertext_modulus
            ));

            let mut output_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(res.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &res, &mut output_plaintext_list);

            let mut decoded = vec![Scalar::ZERO; output_plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(output_plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == Scalar::ZERO));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(glwe_encrypt_sub_decrypt_custom_mod);
