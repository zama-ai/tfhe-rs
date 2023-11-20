use super::*;
#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn glwe_encrypt_sample_extract_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
    params: ClassicTestParams<Scalar>,
) {
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
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

            let equivalent_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

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
                glwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &glwe,
                ciphertext_modulus
            ));

            let mut ser_output_lwe_ciphertext_list = LweCiphertextList::new(
                Scalar::ZERO,
                equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(glwe.polynomial_size().0),
                ciphertext_modulus,
            );

            for (idx, mut output_lwe_ciphertext) in
                ser_output_lwe_ciphertext_list.iter_mut().enumerate()
            {
                extract_lwe_sample_from_glwe_ciphertext(
                    &glwe,
                    &mut output_lwe_ciphertext,
                    MonomialDegree(idx),
                );
            }

            assert!(check_encrypted_content_respects_mod(
                &ser_output_lwe_ciphertext_list,
                ciphertext_modulus
            ));

            let mut par_output_lwe_ciphertext_list = LweCiphertextList::new(
                Scalar::ZERO,
                equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(glwe.polynomial_size().0),
                ciphertext_modulus,
            );

            par_extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut par_output_lwe_ciphertext_list);

            assert_eq!(
                ser_output_lwe_ciphertext_list,
                par_output_lwe_ciphertext_list
            );

            let mut plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(ser_output_lwe_ciphertext_list.lwe_ciphertext_count().0),
            );

            decrypt_lwe_ciphertext_list(
                &equivalent_lwe_sk,
                &ser_output_lwe_ciphertext_list,
                &mut plaintext_list,
            );

            let mut decoded = vec![Scalar::ZERO; plaintext_list.plaintext_count().0];

            decoded
                .iter_mut()
                .zip(plaintext_list.iter())
                .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

            assert!(decoded.iter().all(|&x| x == msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(glwe_encrypt_sample_extract_decrypt_custom_mod);
