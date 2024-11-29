use super::*;
use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_async;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use serde::de::DeserializeOwned;
use serde::Serialize;

const NB_TESTS: usize = 10;
fn generate_keys<Scalar: UnsignedTorus + Sync + Send + Serialize + DeserializeOwned>(
    params: PackingKeySwitchTestParams<Scalar>,
    streams: &CudaStreams,
    rsc: &mut TestResources,
) -> CudaPackingKeySwitchKeys<Scalar> {
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
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &pksk,
        params.ciphertext_modulus
    ));

    let cuda_pksk = CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(&pksk, streams);

    CudaPackingKeySwitchKeys {
        lwe_sk,
        glwe_sk,
        pksk: cuda_pksk,
    }
}

fn lwe_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar, P>(params: P)
where
    Scalar: UnsignedTorus + CastInto<usize> + Serialize + DeserializeOwned,
    P: Into<PackingKeySwitchTestParams<Scalar>>,
    PackingKeySwitchTestParams<Scalar>: KeyCacheAccess<Keys = PackingKeySwitchKeys<Scalar>>,
{
    let params = params.into();

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let keys = generate_keys(params, &stream, &mut rsc);
            let (pksk, lwe_sk, glwe_sk) = (keys.pksk, keys.lwe_sk, keys.glwe_sk);

            let plaintext = Plaintext(msg * delta);

            let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
                &lwe_sk,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let d_input_lwe = CudaLweCiphertextList::from_lwe_ciphertext(&input_lwe, &stream);

            assert!(check_encrypted_content_respects_mod(
                &input_lwe,
                ciphertext_modulus
            ));

            let mut d_output_glwe = CudaGlweCiphertextList::new(
                glwe_sk.glwe_dimension(),
                glwe_sk.polynomial_size(),
                GlweCiphertextCount(1),
                ciphertext_modulus,
                &stream,
            );

            unsafe {
                cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_async(
                    &pksk,
                    &d_input_lwe,
                    &mut d_output_glwe,
                    &stream,
                );
            }
            let output_glwe_list = d_output_glwe.to_glwe_ciphertext_list(&stream);
            let mut decrypted_plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(output_glwe_list.polynomial_size().0),
            );

            decrypt_glwe_ciphertext_list(
                &glwe_sk,
                &output_glwe_list,
                &mut decrypted_plaintext_list,
            );
            let decoded = round_decode(*decrypted_plaintext_list.get(0).0, delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

fn lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod<Scalar, P>(params: P)
where
    Scalar: UnsignedTorus + CastInto<usize> + Serialize + DeserializeOwned,
    P: Into<PackingKeySwitchTestParams<Scalar>>,
    PackingKeySwitchTestParams<Scalar>: KeyCacheAccess<Keys = PackingKeySwitchKeys<Scalar>>,
{
    let params = params.into();

    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let keys = generate_keys(params, &stream, &mut rsc);
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
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            let d_input_lwe_list =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&input_lwe_list, &stream);

            assert!(check_encrypted_content_respects_mod(
                &input_lwe_list,
                ciphertext_modulus
            ));

            let mut d_output_glwe = CudaGlweCiphertextList::new(
                glwe_sk.glwe_dimension(),
                glwe_sk.polynomial_size(),
                GlweCiphertextCount(1),
                ciphertext_modulus,
                &stream,
            );

            unsafe {
                cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_async(
                    &pksk,
                    &d_input_lwe_list,
                    &mut d_output_glwe,
                    &stream,
                );
            }

            let output_glwe_list = d_output_glwe.to_glwe_ciphertext_list(&stream);

            let mut decrypted_plaintext_list = PlaintextList::new(
                Scalar::ZERO,
                PlaintextCount(output_glwe_list.polynomial_size().0),
            );

            decrypt_glwe_ciphertext_list(
                &glwe_sk,
                &output_glwe_list,
                &mut decrypted_plaintext_list,
            );

            decrypted_plaintext_list
                .iter_mut()
                .for_each(|x| *x.0 = round_decode(*x.0, delta) % msg_modulus);
            input_plaintext_list.iter_mut().for_each(|x| *x.0 /= delta);

            assert_eq!(decrypted_plaintext_list, input_plaintext_list);
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

create_gpu_parameterized_test!(lwe_encrypt_pks_to_glwe_decrypt_custom_mod);
create_gpu_parameterized_test!(lwe_list_encrypt_pks_to_glwe_decrypt_custom_mod);
