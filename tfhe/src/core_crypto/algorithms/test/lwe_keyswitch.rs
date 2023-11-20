use super::*;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn lwe_encrypt_ks_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
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
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ksk_big_to_small,
                ciphertext_modulus
            ));

            let plaintext = Plaintext(msg * delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk,
                plaintext,
                lwe_modular_std_dev,
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

            let mut output_ct_parallel = LweCiphertext::new(
                Scalar::ZERO,
                lwe_sk.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                ciphertext_modulus
            ));

            par_keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct_parallel);
            assert_eq!(output_ct.as_ref(), output_ct_parallel.as_ref());

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_encrypt_ks_decrypt_custom_mod);
