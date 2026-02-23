use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
#[cfg(feature = "zk-pok")]
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::test_tools;
#[cfg(feature = "zk-pok")]
use rand::Rng;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn parallel_and_seeded_lwe_list_encryption_equivalence<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCiphertext creation
    let lwe_dimension = params.lwe_dimension;
    let lwe_ciphertext_count = LweCiphertextCount(10);
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let main_seed = seeder.seed();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );
        par_encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut par_lwe_list,
            &plaintext_list,
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut ser_lwe_list = LweCiphertextList::new(
            Scalar::ZERO,
            lwe_dimension.to_lwe_size(),
            lwe_ciphertext_count,
            ciphertext_modulus,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);
        let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            deterministic_seeder.seed(),
            &mut deterministic_seeder,
        );
        encrypt_lwe_ciphertext_list(
            &lwe_secret_key,
            &mut ser_lwe_list,
            &plaintext_list,
            lwe_noise_distribution,
            &mut encryption_generator,
        );

        assert_eq!(par_lwe_list, ser_lwe_list);

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);
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
            lwe_noise_distribution,
            &mut deterministic_seeder,
        );

        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(main_seed);

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
            lwe_noise_distribution,
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

create_parameterized_test!(parallel_and_seeded_lwe_list_encryption_equivalence {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_63_U64,
    DUMMY_NATIVE_U32,
    DUMMY_31_U32,
});

fn lwe_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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

            // This may look silly, but this is to catch a regression where the previous content of
            // the ciphertext was wrongly used during encryption, re-encrypting in a ciphertext
            // where we already encrypted allows to check the encryption is valid even if the
            // destination LWE is dirty
            for _ in 0..2 {
                encrypt_lwe_ciphertext(
                    &lwe_sk,
                    &mut ct,
                    plaintext,
                    lwe_noise_distribution,
                    &mut rsc.encryption_random_generator,
                );

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus,
                ));

                let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(msg, decoded);
            }
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_encrypt_decrypt_custom_mod);

fn lwe_allocate_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_allocate_encrypt_decrypt_custom_mod);

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
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}
create_parameterized_test_with_non_native_parameters!(lwe_trivial_encrypt_decrypt_custom_mod);

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
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(
    lwe_allocate_trivial_encrypt_decrypt_custom_mod
);

fn lwe_list_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &list,
                ciphertext_modulus,
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
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_list_encrypt_decrypt_custom_mod);

fn lwe_list_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &list,
                ciphertext_modulus,
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
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_list_par_encrypt_decrypt_custom_mod);

fn lwe_public_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
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
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_public_encrypt_decrypt_custom_mod);

fn lwe_seeded_public_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
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
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(lwe_seeded_public_encrypt_decrypt_custom_mod);

fn lwe_seeded_list_par_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus + Sync + Send>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &seeded_list,
                ciphertext_modulus,
            ));

            let mut plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(seeded_list.lwe_ciphertext_count().0),
            );

            let lwe_list = seeded_list.decompress_into_lwe_ciphertext_list();

            assert!(check_encrypted_content_respects_mod(
                &lwe_list,
                ciphertext_modulus,
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
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(lwe_seeded_list_par_encrypt_decrypt_custom_mod);

fn lwe_seeded_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(params: ClassicTestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &std::slice::from_ref(seeded_ct.get_body().data),
                ciphertext_modulus,
            ));

            let ct = seeded_ct.decompress_into_lwe_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(lwe_seeded_encrypt_decrypt_custom_mod);

fn lwe_seeded_allocate_encrypt_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
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
                lwe_noise_distribution,
                ciphertext_modulus,
                rsc.seeder.as_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &std::slice::from_ref(seeded_ct.get_body().data),
                ciphertext_modulus,
            ));

            let ct = seeded_ct.decompress_into_lwe_ciphertext();

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test_with_non_native_parameters!(
    lwe_seeded_allocate_encrypt_decrypt_custom_mod
);

#[test]
fn test_u128_encryption() {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCiphertext creation
    let lwe_dimension = LweDimension(742);
    let lwe_noise_distribution =
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.998_277_131_225_527e-11));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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
                lwe_noise_distribution,
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
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let pk = allocate_and_generate_new_lwe_compact_public_key(
                &lwe_sk,
                glwe_noise_distribution,
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
                glwe_noise_distribution,
                glwe_noise_distribution,
                rsc.encryption_random_generator.noise_generator_mut(),
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus,
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_parameterized_test!(lwe_compact_public_encrypt_decrypt_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});

#[cfg(feature = "zk-pok")]
fn lwe_compact_public_encrypt_prove_verify_decrypt_custom_mod<Scalar>(
    params: ClassicTestParams<Scalar>,
) where
    Scalar: UnsignedTorus + CastFrom<u64>,
    Scalar::Signed: CastFrom<u64>,
    i64: CastFrom<Scalar>,
    u64: CastFrom<Scalar> + CastInto<Scalar::Signed>,
    rand_distr::Standard: rand_distr::Distribution<Scalar>,
{
    use crate::zk::ZkMSBZeroPaddingBitCount;
    let lwe_dimension = LweDimension(params.polynomial_size.0);
    let glwe_noise_distribution = TUniform::new(9);
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let metadata = [b'c', b'o', b'r', b'e'];

    let mut rsc = TestResources::new();
    let mut random_generator = RandomGenerator::<DefaultRandomGenerator>::new(rsc.seeder.seed());

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    // Test zk scheme v1 and v2
    let crs_v2 = CompactPkeCrs::new(
        lwe_dimension,
        LweCiphertextCount(1),
        glwe_noise_distribution,
        ciphertext_modulus,
        msg_modulus * Scalar::TWO,
        ZkMSBZeroPaddingBitCount(1),
        &mut random_generator,
    )
    .unwrap();

    let crs_v1 = CompactPkeCrs::new_legacy_v1(
        lwe_dimension,
        LweCiphertextCount(1),
        glwe_noise_distribution,
        ciphertext_modulus,
        msg_modulus * Scalar::TWO,
        ZkMSBZeroPaddingBitCount(1),
        &mut random_generator,
    )
    .unwrap();

    for crs in [&crs_v2, &crs_v1] {
        while msg != Scalar::ZERO {
            msg = msg.wrapping_sub(Scalar::ONE);
            for _ in 0..NB_TESTS {
                let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                    lwe_dimension,
                    &mut rsc.secret_random_generator,
                );

                let pk = allocate_and_generate_new_lwe_compact_public_key(
                    &lwe_sk,
                    glwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.encryption_random_generator,
                );

                let mut ct = LweCiphertext::new(
                    Scalar::ZERO,
                    lwe_dimension.to_lwe_size(),
                    ciphertext_modulus,
                );

                let proof = encrypt_and_prove_lwe_ciphertext_with_compact_public_key(
                    &pk,
                    &mut ct,
                    Cleartext(msg),
                    delta,
                    glwe_noise_distribution,
                    glwe_noise_distribution,
                    rsc.encryption_random_generator.noise_generator_mut(),
                    &mut random_generator,
                    crs,
                    &metadata,
                    ZkComputeLoad::Proof,
                )
                .unwrap();

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus,
                ));

                let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(msg, decoded);

                // Verify the proof
                assert!(verify_lwe_ciphertext(&ct, &pk, &proof, crs, &metadata).is_valid());

                // verify proof with invalid ciphertext
                let index = random_generator.gen::<usize>() % ct.as_ref().len();
                let value_to_add = random_generator.gen::<Scalar>();
                ct.as_mut()[index] = ct.as_mut()[index].wrapping_add(value_to_add);
                assert!(verify_lwe_ciphertext(&ct, &pk, &proof, crs, &metadata).is_invalid());
            }

            // In coverage, we break after one while loop iteration, changing message values does
            // not yield higher coverage
            #[cfg(tarpaulin)]
            break;
        }
    }
}

#[cfg(feature = "zk-pok")]
create_parameterized_test!(lwe_compact_public_encrypt_prove_verify_decrypt_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});

#[cfg(feature = "zk-pok")]
#[test]
fn test_par_compact_lwe_list_public_key_encryption_and_proof() {
    use crate::zk::ZkMSBZeroPaddingBitCount;
    use rand::Rng;

    let lwe_dimension = LweDimension(2048);
    let glwe_noise_distribution = TUniform::new(9);
    let ciphertext_modulus = CiphertextModulus::new_native();

    let metadata = [b'c', b'o', b'r', b'e'];

    let delta_log = 59;
    let delta = 1u64 << delta_log;
    let msb_zero_padding_bit_count = ZkMSBZeroPaddingBitCount(1);
    let message_modulus = 1u64 << (64 - (delta_log + msb_zero_padding_bit_count.0));
    let plaintext_modulus = 1u64 << (64 - delta_log);
    let mut thread_rng = rand::rng();

    let max_num_body = 512;
    let crs = CompactPkeCrs::new(
        lwe_dimension,
        LweCiphertextCount(max_num_body),
        glwe_noise_distribution,
        ciphertext_modulus,
        plaintext_modulus,
        msb_zero_padding_bit_count,
        &mut thread_rng,
    )
    .unwrap();

    for _ in 0..4 {
        let ct_count = thread_rng.gen_range(1..=max_num_body);
        let lwe_ciphertext_count = LweCiphertextCount(ct_count);

        println!("{lwe_dimension:?} {ct_count:?}");

        let seed = test_tools::random_seed();
        let cleartexts = (0..ct_count)
            .map(|_| thread_rng.gen::<u64>() % message_modulus)
            .collect::<Vec<_>>();

        let par_lwe_ct_list = {
            let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
            let mut random_generator =
                RandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());
            let mut secret_random_generator =
                SecretRandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());
            let mut encryption_random_generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
                    deterministic_seeder.seed(),
                    &mut deterministic_seeder,
                );

            let lwe_sk =
                LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

            let mut compact_lwe_pk =
                LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

            generate_lwe_compact_public_key(
                &lwe_sk,
                &mut compact_lwe_pk,
                glwe_noise_distribution,
                &mut encryption_random_generator,
            );

            let mut output_compact_ct_list = LweCompactCiphertextList::new(
                0u64,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                ciphertext_modulus,
            );

            let proof = par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                &compact_lwe_pk,
                &mut output_compact_ct_list,
                &cleartexts,
                delta,
                glwe_noise_distribution,
                glwe_noise_distribution,
                encryption_random_generator.noise_generator_mut(),
                &mut random_generator,
                &crs,
                &metadata,
                ZkComputeLoad::Proof,
            )
            .unwrap();

            assert!(verify_lwe_compact_ciphertext_list(
                &output_compact_ct_list,
                &compact_lwe_pk,
                &proof,
                &crs,
                &metadata
            )
            .is_valid());

            let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(ct_count));

            let lwe_ciphertext_list = output_compact_ct_list
                .clone()
                .par_expand_into_lwe_ciphertext_list();

            decrypt_lwe_ciphertext_list(&lwe_sk, &lwe_ciphertext_list, &mut output_plaintext_list);

            let signed_decomposer =
                SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

            output_plaintext_list
                .iter_mut()
                .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0) >> delta_log);

            assert_eq!(cleartexts.as_slice(), output_plaintext_list.as_ref());

            // verify proof with invalid ciphertext
            let index = random_generator.gen::<usize>() % output_compact_ct_list.as_ref().len();
            let value_to_add = random_generator.gen();
            output_compact_ct_list.as_mut()[index] =
                output_compact_ct_list.as_mut()[index].wrapping_add(value_to_add);
            assert!(verify_lwe_compact_ciphertext_list(
                &output_compact_ct_list,
                &compact_lwe_pk,
                &proof,
                &crs,
                &metadata
            )
            .is_invalid());

            lwe_ciphertext_list
        };

        let ser_lwe_ct_list = {
            let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
            let mut random_generator =
                RandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());
            let mut secret_random_generator =
                SecretRandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());
            let mut encryption_random_generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
                    deterministic_seeder.seed(),
                    &mut deterministic_seeder,
                );

            let lwe_sk =
                LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

            let mut compact_lwe_pk =
                LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

            generate_lwe_compact_public_key(
                &lwe_sk,
                &mut compact_lwe_pk,
                glwe_noise_distribution,
                &mut encryption_random_generator,
            );

            let mut output_compact_ct_list = LweCompactCiphertextList::new(
                0u64,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                ciphertext_modulus,
            );

            let proof = par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
                &compact_lwe_pk,
                &mut output_compact_ct_list,
                &cleartexts,
                delta,
                glwe_noise_distribution,
                glwe_noise_distribution,
                encryption_random_generator.noise_generator_mut(),
                &mut random_generator,
                &crs,
                &metadata,
                ZkComputeLoad::Proof,
            )
            .unwrap();

            assert!(verify_lwe_compact_ciphertext_list(
                &output_compact_ct_list,
                &compact_lwe_pk,
                &proof,
                &crs,
                &metadata
            )
            .is_valid());

            let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(ct_count));

            let lwe_ciphertext_list = output_compact_ct_list
                .clone()
                .expand_into_lwe_ciphertext_list();

            decrypt_lwe_ciphertext_list(&lwe_sk, &lwe_ciphertext_list, &mut output_plaintext_list);

            let signed_decomposer =
                SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

            output_plaintext_list
                .iter_mut()
                .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0) >> delta_log);

            assert_eq!(cleartexts.as_slice(), output_plaintext_list.as_ref());

            // verify proof with invalid ciphertext
            let index = random_generator.gen::<usize>() % output_compact_ct_list.as_ref().len();
            let value_to_add = random_generator.gen();
            output_compact_ct_list.as_mut()[index] =
                output_compact_ct_list.as_mut()[index].wrapping_add(value_to_add);
            assert!(verify_lwe_compact_ciphertext_list(
                &output_compact_ct_list,
                &compact_lwe_pk,
                &proof,
                &crs,
                &metadata
            )
            .is_invalid());

            lwe_ciphertext_list
        };

        assert_eq!(ser_lwe_ct_list, par_lwe_ct_list);
    }
}
