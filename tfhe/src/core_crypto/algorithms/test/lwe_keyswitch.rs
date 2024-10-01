use super::*;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn lwe_encrypt_ks_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
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
                lwe_noise_distribution,
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
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_encrypt_ks_decrypt_custom_mod);

#[test]
fn test_lwe_encrypt_ks_switch_mod_decrypt_custom_mod() {
    let params = super::TEST_PARAMS_4_BITS_NATIVE_U64;

    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let input_ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let input_encoding_with_padding = get_encoding_with_padding(input_ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    let output_ciphertext_modulus = CiphertextModulus::<u64>::try_new_power_of_2(32).unwrap();
    let output_encoding_with_padding = get_encoding_with_padding(output_ciphertext_modulus);

    // Try to have a 32 bits modulus for the output
    assert!(ks_decomp_base_log.0 * ks_decomp_level_count.0 <= 32);

    let mut rsc = TestResources::new();

    let msg_modulus = 1u64 << message_modulus_log.0;
    let mut msg = msg_modulus;
    let input_delta = input_encoding_with_padding / msg_modulus;
    let output_delta = output_encoding_with_padding / msg_modulus;

    while msg != 0 {
        msg -= 1;
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
                lwe_noise_distribution,
                output_ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ksk_big_to_small,
                output_ciphertext_modulus
            ));

            let plaintext = Plaintext(msg * input_delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk,
                plaintext,
                lwe_noise_distribution,
                input_ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                input_ciphertext_modulus
            ));

            let mut output_ct = LweCiphertext::new(
                0u64,
                lwe_sk.lwe_dimension().to_lwe_size(),
                output_ciphertext_modulus,
            );

            let mut output_ct_parallel = LweCiphertext::new(
                0u64,
                lwe_sk.lwe_dimension().to_lwe_size(),
                output_ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                output_ciphertext_modulus
            ));

            par_keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct_parallel);
            assert_eq!(output_ct.as_ref(), output_ct_parallel.as_ref());

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

            let decoded = round_decode(decrypted.0, output_delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

#[test]
fn test_lwe_encrypt_ks_switch_mod_switch_scalar_decrypt_custom_mod() {
    let params = super::TEST_PARAMS_4_BITS_NATIVE_U64;

    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution_u64 = params.lwe_noise_distribution;
    // DICLAIMER: This is just for demonstration purposes, parameters are not guaranteed to be
    // secure or yield correct computations.
    let lwe_noise_distribution_u32 =
        DynamicDistribution::new_gaussian(lwe_noise_distribution_u64.gaussian_std_dev());
    let input_ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let input_encoding_with_padding = get_encoding_with_padding(input_ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    let output_ciphertext_modulus = CiphertextModulus::<u32>::new_native();
    let output_encoding_with_padding = get_encoding_with_padding(output_ciphertext_modulus);

    // Try to have a 32 bits modulus for the output
    assert!(ks_decomp_base_log.0 * ks_decomp_level_count.0 <= 32);

    let mut rsc = TestResources::new();

    let input_msg_modulus = 1u64 << message_modulus_log.0;
    let output_msg_modulus = 1u32 << message_modulus_log.0;
    let mut msg = input_msg_modulus;
    let input_delta = input_encoding_with_padding / input_msg_modulus;
    let output_delta = output_encoding_with_padding / output_msg_modulus;

    while msg != 0 {
        msg -= 1;
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key::<u32, _>(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let big_lwe_sk_u64 = glwe_sk.as_lwe_secret_key();

            let big_lwe_sk_u32 = LweSecretKey::from_container(
                glwe_sk
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|x| x as u32)
                    .collect::<Vec<_>>(),
            );

            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &big_lwe_sk_u32,
                &lwe_sk,
                ks_decomp_base_log,
                ks_decomp_level_count,
                lwe_noise_distribution_u32,
                output_ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ksk_big_to_small,
                output_ciphertext_modulus
            ));

            let plaintext = Plaintext(msg * input_delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk_u64,
                plaintext,
                lwe_noise_distribution_u64,
                input_ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                input_ciphertext_modulus
            ));

            let mut output_ct = LweCiphertext::new(
                0u32,
                lwe_sk.lwe_dimension().to_lwe_size(),
                output_ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_with_scalar_change(&ksk_big_to_small, &ct, &mut output_ct);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                output_ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

            let decoded = round_decode(decrypted.0, output_delta) % output_msg_modulus;

            assert_eq!(msg as u32, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}
