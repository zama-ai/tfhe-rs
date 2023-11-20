use super::*;
use crate::core_crypto::keycache::KeyCacheAccess;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;

fn generate_keys<Scalar: UnsignedTorus + Sync + Send + Serialize + DeserializeOwned>(
    params: PackingKeySwitchTestParams<Scalar>,
    rsc: &mut TestResources,
) -> PackingKeySwitchKeys<Scalar> {
    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
        params.lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
        &lwe_sk,
        &glwe_sk,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_modular_std_dev,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &pksk,
        params.ciphertext_modulus
    ));

    PackingKeySwitchKeys {
        lwe_sk,
        glwe_sk,
        pksk,
    }
}
fn lwe_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar, P>(params: P)
where
    Scalar: UnsignedTorus + Serialize + DeserializeOwned,
    P: Into<PackingKeySwitchTestParams<Scalar>>,
    PackingKeySwitchTestParams<Scalar>: KeyCacheAccess<Keys = PackingKeySwitchKeys<Scalar>>,
{
    let params = params.into();

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
            let mut keys_gen = |params| generate_keys(params, &mut rsc);
            let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
            let (pksk, lwe_sk, glwe_sk) = (keys.pksk, keys.lwe_sk, keys.glwe_sk);

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

            let mut output_ct = GlweCiphertext::new(
                Scalar::ZERO,
                glwe_sk.glwe_dimension().to_glwe_size(),
                glwe_sk.polynomial_size(),
                ciphertext_modulus,
            );

            keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &ct, &mut output_ct);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                ciphertext_modulus
            ));

            let mut decrypted_plaintext_list =
                PlaintextList::new(Scalar::ZERO, PlaintextCount(output_ct.polynomial_size().0));

            decrypt_glwe_ciphertext(&glwe_sk, &output_ct, &mut decrypted_plaintext_list);

            let decoded = round_decode(*decrypted_plaintext_list.get(0).0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_encrypt_pks_to_glwe_decrypt_custom_mod);

fn lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar, P>(params: P)
where
    Scalar: UnsignedTorus + Serialize + DeserializeOwned,
    P: Into<PackingKeySwitchTestParams<Scalar>>,
    PackingKeySwitchTestParams<Scalar>: KeyCacheAccess<Keys = PackingKeySwitchKeys<Scalar>>,
{
    let params = params.into();

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
            let mut keys_gen = |params| generate_keys(params, &mut rsc);
            let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
            let (pksk, lwe_sk, glwe_sk) = (keys.pksk, keys.lwe_sk, keys.glwe_sk);

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

            assert!(check_encrypted_content_respects_mod(
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

            assert!(check_encrypted_content_respects_mod(
                &output_glwe,
                ciphertext_modulus
            ));

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

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(feature = "__coverage")]
        break;
    }
}

create_parametrized_test!(lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod);
