use super::*;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(not(feature = "__coverage"))]
// Cut down heavy tests
const NB_TESTS_LIGHT: usize = 5;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;
#[cfg(feature = "__coverage")]
const NB_TESTS_LIGHT: usize = 1;

fn lwe_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar: UnsignedTorus>(params: TestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

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

            let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
                &lwe_sk,
                &glwe_sk,
                decomp_base_log,
                decomp_level_count,
                glwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&pksk, ciphertext_modulus));

            let plaintext = Plaintext(msg * delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&ct, ciphertext_modulus));

            let mut output_ct = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_sk.glwe_dimension().to_glwe_size(),
                glwe_sk.polynomial_size(),
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &ct, &mut output_ct);

            assert!(check_content_respects_mod(&output_ct, ciphertext_modulus));

            let mut decrypted_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(output_ct.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &output_ct, &mut decrypted_plaintext_list);

            let decoded = round_decode(*decrypted_plaintext_list.get(0).0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }
    }
}

create_parametrized_test!(lwe_encrypt_pks_to_glwe_decrypt_custom_mod);

fn lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
    params: TestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS_LIGHT {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );

            let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
                &lwe_sk,
                &glwe_sk,
                decomp_base_log,
                decomp_level_count,
                glwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&pksk, ciphertext_modulus));

            let mut input_lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(glwe_sk.polynomial_size().0),
                ciphertext_modulus,
            );

            let mut input_plaintext_list =
                PlaintextList::new(msg * delta, PlaintextCount(glwe_sk.polynomial_size().0));

            encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut input_lwe_list,
                &input_plaintext_list,
                lwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(
                &input_lwe_list,
                ciphertext_modulus
            ));

            let mut output_glwe = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_sk.glwe_dimension().to_glwe_size(),
                glwe_sk.polynomial_size(),
                ciphertext_modulus,
            );

            let mut output_glwe_parallel = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_sk.glwe_dimension().to_glwe_size(),
                glwe_sk.polynomial_size(),
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &pksk,
                &input_lwe_list,
                &mut output_glwe,
            );

            assert!(check_content_respects_mod(&output_glwe, ciphertext_modulus));

            par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                &pksk,
                &input_lwe_list,
                &mut output_glwe_parallel,
            );

            assert_eq!(output_glwe.as_ref(), output_glwe_parallel.as_ref());

            let mut decrypted_plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(output_glwe.polynomial_size().0),
            );

            decrypt_glwe_ciphertext(&glwe_sk, &output_glwe, &mut decrypted_plaintext_list);

            decrypted_plaintext_list
                .iter_mut()
                .for_each(|x| *x.0 = round_decode(*x.0, delta) % msg_modulus);
            input_plaintext_list.iter_mut().for_each(|x| *x.0 /= delta);

            assert_eq!(decrypted_plaintext_list, input_plaintext_list);
        }
    }
}

create_parametrized_test!(lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod);
