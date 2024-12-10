use super::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::glwe_sample_extraction::cuda_extract_lwe_samples_from_glwe_ciphertext_list;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use itertools::Itertools;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn glwe_encrypt_sample_extract_decrypt_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
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
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    let mut msgs = vec![];

    // Build msg
    // TODO: Can't we collect from (0..msg_modulus) if msg_modulus is Scalar?
    let mut msg = msg_modulus;
    msg = msg.wrapping_sub(Scalar::ONE);
    while msg != Scalar::ZERO {
        msgs.push(msg);
        msg = msg.wrapping_sub(Scalar::ONE);
    }

    // Run tests
    for _ in 0..NB_TESTS {
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut rsc.secret_random_generator,
        );

        let equivalent_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        let mut glwe_list = GlweCiphertextList::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            GlweCiphertextCount(msgs.len()),
            ciphertext_modulus,
        );

        let cleartext_list = msgs
            .iter()
            .flat_map(|&x| vec![x * delta; glwe_list.polynomial_size().0])
            .collect_vec();

        let plaintext_list = PlaintextList::from_container(cleartext_list);
        encrypt_glwe_ciphertext_list(
            &glwe_sk,
            &mut glwe_list,
            &plaintext_list,
            glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        let input_cuda_glwe_list =
            CudaGlweCiphertextList::from_glwe_ciphertext_list(&glwe_list, &streams);

        let mut output_cuda_lwe_ciphertext_list = CudaLweCiphertextList::new(
            equivalent_lwe_sk.lwe_dimension(),
            LweCiphertextCount(msgs.len() * glwe_list.polynomial_size().0),
            ciphertext_modulus,
            &streams,
        );

        let nths = (0..(msgs.len() * glwe_list.polynomial_size().0))
            .map(|x| MonomialDegree(x % glwe_list.polynomial_size().0))
            .collect_vec();

        cuda_extract_lwe_samples_from_glwe_ciphertext_list(
            &input_cuda_glwe_list,
            &mut output_cuda_lwe_ciphertext_list,
            nths.as_slice(),
            &streams,
        );

        let gpu_output_lwe_ciphertext_list =
            output_cuda_lwe_ciphertext_list.to_lwe_ciphertext_list(&streams);

        let mut output_plaintext_list = PlaintextList::new(
            Scalar::ZERO,
            PlaintextCount(gpu_output_lwe_ciphertext_list.lwe_ciphertext_count().0),
        );

        decrypt_lwe_ciphertext_list(
            &equivalent_lwe_sk,
            &gpu_output_lwe_ciphertext_list,
            &mut output_plaintext_list,
        );

        let mut decoded = vec![Scalar::ZERO; plaintext_list.plaintext_count().0];

        decoded
            .iter_mut()
            .zip(output_plaintext_list.iter())
            .for_each(|(dst, src)| *dst = round_decode(*src.0, delta) % msg_modulus);

        let mut count = msg_modulus;
        count = count.wrapping_sub(Scalar::ONE);
        for result in decoded.chunks_exact(glwe_list.polynomial_size().0) {
            assert!(result.iter().all(|&x| x == count));
            count = count.wrapping_sub(Scalar::ONE);
        }
    }
}

create_gpu_parameterized_test!(glwe_encrypt_sample_extract_decrypt_custom_mod);
