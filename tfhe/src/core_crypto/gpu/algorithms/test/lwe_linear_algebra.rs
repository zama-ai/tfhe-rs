use super::*;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{cuda_lwe_ciphertext_add_assign, CudaDevice, CudaStream};

fn lwe_encrypt_add_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
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
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let rhs = ct.clone();

            // Convert to CUDA objects
            let mut d_ct = CudaLweCiphertextList::from_lwe_ciphertext(&ct, &stream);
            let d_rhs = CudaLweCiphertextList::from_lwe_ciphertext(&rhs, &stream);

            cuda_lwe_ciphertext_add_assign(&mut d_ct, &d_rhs, &stream);

            let output = d_ct.into_lwe_ciphertext(&stream);

            assert!(check_encrypted_content_respects_mod(
                &output,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!((msg + msg) % msg_modulus, decoded);
        }
    }
}

create_gpu_parametrized_test!(lwe_encrypt_add_assign_decrypt_custom_mod);
