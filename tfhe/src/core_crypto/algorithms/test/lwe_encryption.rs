use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::test_tools;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn parallel_and_seeded_lwe_list_encryption_equivalence<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCiphertext creation
    let lwe_dimension = params.lwe_dimension;
    let lwe_ciphertext_count = LweCiphertextCount(10);
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let main_seed = seeder.seed();

    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    for _ in 0..NB_TESTS {
        // Create the LweSecretKey
        let lwe_secret_key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
        // Create the plaintext
        let msg: Scalar = test_tools::random_uint_between(Scalar::ZERO..Scalar::TWO.shl(2));
        let encoded_msg = msg << (Scalar::BITS - 4);
        let plaintext_list =
            PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
        // Create a new LweCiphertextList
        let mut par_lwe_list = LweCiphertextList::new(
            Scalar::ZERO,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );
        par_encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut par_lwe_list,
            &plaintext_list,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        let mut ser_lwe_list = LweCiphertextList::new(
            Scalar::ZERO,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut ser_lwe_list,
            &plaintext_list,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        assert_eq!(par_lwe_list, ser_lwe_list);

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
        // Create a new LweCiphertextList
        let mut par_seeded_lwe_list = SeededLweCiphertextList::new(
            Scalar::ZERO,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            deterministic_seeder.seed().into(),
            ciphertext_modulus,
        );

        par_encrypt_seeded_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut par_seeded_lwe_list,
            &plaintext_list,
            lwe_modular_std_dev,
            &mut deterministic_seeder,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

        let mut ser_seeded_lwe_list = SeededLweCiphertextList::new(
            Scalar::ZERO,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            deterministic_seeder.seed().into(),
            ciphertext_modulus,
        );

        encrypt_seeded_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut ser_seeded_lwe_list,
            &plaintext_list,
            lwe_modular_std_dev,
            &mut deterministic_seeder,
        );

        assert_eq!(par_seeded_lwe_list, ser_seeded_lwe_list);

        let ser_decompressed_lwe_list = ser_seeded_lwe_list.decompress_into_lwe_ciphertext_list();

        assert_eq!(ser_decompressed_lwe_list, ser_lwe_list);

        let par_decompressed_lwe_list =
            par_seeded_lwe_list.par_decompress_into_lwe_ciphertext_list();

        assert_eq!(par_decompressed_lwe_list, ser_decompressed_lwe_list);
    }
}

create_parametrized_test!(parallel_and_seeded_lwe_list_encryption_equivalence {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_63_U64,
    DUMMY_NATIVE_U32,
    DUMMY_31_U32,
});

fn lwe_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(lwe_encrypt_decrypt_custom_mod);

fn lwe_allocate_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let plaintext = Plaintext(msg * delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(lwe_allocate_encrypt_decrypt_custom_mod);

fn lwe_trivial_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
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

            trivially_encrypt_lwe_ciphertext(&mut ct, plaintext);

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}
create_parametrized_test_with_non_native_parameters!(lwe_trivial_encrypt_decrypt_custom_mod);

fn lwe_allocate_trivial_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
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
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let plaintext = Plaintext(msg * delta);

            let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                lwe_dimension.to_lwe_size(),
                plaintext,
                ciphertext_modulus,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(
    lwe_allocate_trivial_encrypt_decrypt_custom_mod
);

fn lwe_list_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ct_count = LweCiphertextCount(10);

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

            let mut list = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ct_count,
                ciphertext_modulus,
            );

            let encoded_list =
                PlaintextList::new(msg * delta, PlaintextCount(list.lwe_ciphertext_count().0));

            encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut list,
                &encoded_list,
                lwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &list,
                ciphertext_modulus
            ));

            let mut plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(list.lwe_ciphertext_count().0));

            decrypt_lwe_ciphertext_list(&lwe_sk, &list, &mut plaintext_list);

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

create_parametrized_test_with_non_native_parameters!(lwe_list_encrypt_decrypt_custom_mod);

fn lwe_list_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ct_count = LweCiphertextCount(10);

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

            let mut list = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ct_count,
                ciphertext_modulus,
            );

            let encoded_list =
                PlaintextList::new(msg * delta, PlaintextCount(list.lwe_ciphertext_count().0));

            par_encrypt_lwe_ciphertext_list(
                &lwe_sk,
                &mut list,
                &encoded_list,
                lwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &list,
                ciphertext_modulus
            ));

            let mut plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(list.lwe_ciphertext_count().0));

            decrypt_lwe_ciphertext_list(&lwe_sk, &list, &mut plaintext_list);

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

create_parametrized_test_with_non_native_parameters!(lwe_list_par_encrypt_decrypt_custom_mod);

fn lwe_public_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let zero_encryption_count = LwePublicKeyZeroEncryptionCount(10);

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

            let pk = allocate_and_generate_new_lwe_public_key(
                &lwe_sk,
                zero_encryption_count,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext_with_public_key(
                &pk,
                &mut ct,
                plaintext,
                &mut rsc.secret_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(lwe_public_encrypt_decrypt_custom_mod);

fn lwe_seeded_public_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let zero_encryption_count = LwePublicKeyZeroEncryptionCount(10);

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

            let mut seeded_pk = SeededLwePublicKey::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                zero_encryption_count,
                rsc.seeder.seed().into(),
                ciphertext_modulus,
            );

            generate_seeded_lwe_public_key(
                &lwe_sk,
                &mut seeded_pk,
                lwe_modular_std_dev,
                rsc.seeder.as_mut(),
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext_with_seeded_public_key(
                &seeded_pk,
                &mut ct,
                plaintext,
                &mut rsc.secret_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_seeded_public_encrypt_decrypt_custom_mod);

fn lwe_seeded_list_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ct_count = LweCiphertextCount(10);

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

            let mut seeded_list = SeededLweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ct_count,
                rsc.seeder.seed().into(),
                ciphertext_modulus,
            );

            let encoded_list = PlaintextList::new(
                msg * delta,
                PlaintextCount(seeded_list.lwe_ciphertext_count().0),
            );

            par_encrypt_seeded_lwe_ciphertext_list(
                &lwe_sk,
                &mut seeded_list,
                &encoded_list,
                lwe_modular_std_dev,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &seeded_list,
                ciphertext_modulus
            ));

            let mut plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(seeded_list.lwe_ciphertext_count().0),
            );

            let lwe_list = seeded_list.decompress_into_lwe_ciphertext_list();

            assert!(check_encrypted_content_respects_mod(
                &lwe_list,
                ciphertext_modulus
            ));

            decrypt_lwe_ciphertext_list(&lwe_sk, &lwe_list, &mut plaintext_list);

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

create_parametrized_test!(lwe_seeded_list_par_encrypt_decrypt_custom_mod);

fn lwe_seeded_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let mut seeded_ct = SeededLweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                rsc.seeder.seed().into(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_seeded_lwe_ciphertext(
                &lwe_sk,
                &mut seeded_ct,
                plaintext,
                lwe_modular_std_dev,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &std::slice::from_ref(seeded_ct.get_body().data),
                ciphertext_modulus
            ));

            let ct = seeded_ct.decompress_into_lwe_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(lwe_seeded_encrypt_decrypt_custom_mod);

fn lwe_seeded_allocate_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
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
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let plaintext = Plaintext(msg * delta);

            let seeded_ct = allocate_and_encrypt_new_seeded_lwe_ciphertext(
                &lwe_sk,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &std::slice::from_ref(seeded_ct.get_body().data),
                ciphertext_modulus
            ));

            let ct = seeded_ct.decompress_into_lwe_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test_with_non_native_parameters!(
    lwe_seeded_allocate_encrypt_decrypt_custom_mod
);

#[test]
fn test_u128_encryption() {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCiphertext creation
    let lwe_dimension = LweDimension(742);
    let lwe_modular_std_dev = StandardDev(4.998_277_131_225_527e-11);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    const MSG_BITS: u32 = 4;

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            // Create the plaintext
            const ENCODING: u32 = u128::BITS - MSG_BITS;
            let plaintext = Plaintext(msg << ENCODING);

            // Create a new LweCiphertext
            let mut lwe = LweCiphertext::new(
                0u128,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );

            encrypt_lwe_ciphertext(
                &lwe_secret_key,
                &mut lwe,
                plaintext,
                lwe_modular_std_dev,
                &mut encryption_generator,
            );

            let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

            // Round and remove encoding
            // First create a decomposer working on the high 4 bits corresponding to our
            // encoding.
            let decomposer = SignedDecomposer::new(
                DecompositionBaseLog(MSG_BITS as usize),
                DecompositionLevelCount(1),
            );

            let rounded = decomposer.closest_representable(decrypted_plaintext.0);

            // Remove the encoding
            let cleartext = rounded >> ENCODING;

            // Check we recovered the original message
            assert_eq!(cleartext, msg);
        }
    }
}

fn lwe_compact_public_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = LweDimension(params.polynomial_size.0);
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

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_compact_public_encrypt_decrypt_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});
