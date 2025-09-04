use super::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext, CudaStreams,
};
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;
use itertools::Itertools;

fn execute_multibit_bootstrap_u128(
    squash_params: NoiseSquashingMultiBitTestParameters<u128>,
    input_params: MultiBitTestParams<u64>,
) {
    let input_lwe_dimension = input_params.input_lwe_dimension;
    let lwe_noise_distribution = input_params.lwe_noise_distribution;
    let glwe_noise_distribution = squash_params.glwe_noise_distribution;
    let ciphertext_modulus = squash_params.ciphertext_modulus;
    let ciphertext_modulus_64 = CiphertextModulus::new_native();
    let msg_modulus = input_params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let encoding_with_padding_64: u64 = get_encoding_with_padding(ciphertext_modulus_64);
    let glwe_dimension = squash_params.glwe_dimension;
    let polynomial_size = squash_params.polynomial_size;
    let decomp_base_log = squash_params.decomp_base_log;
    let decomp_level_count = squash_params.decomp_level_count;
    let grouping_factor = squash_params.grouping_factor;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let mut rsc = TestResources::new();

    let f = |x: u128| x % msg_modulus.0 as u128;

    let delta = encoding_with_padding / msg_modulus.0 as u128;
    let delta_64 = encoding_with_padding_64 / msg_modulus.0 as u64;
    const NB_TESTS: usize = 10;
    for number_of_messages in [1_usize, 2_usize, 100_usize] {
        let mut msg = msg_modulus.0 as u64;

        let accumulator = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            msg_modulus.0.cast_into(),
            ciphertext_modulus,
            delta,
            f,
        );

        assert!(check_encrypted_content_respects_mod(
            &accumulator,
            ciphertext_modulus
        ));

        // Create the LweSecretKey
        let small_lwe_sk: LweSecretKeyOwned<u128> = allocate_and_generate_new_binary_lwe_secret_key(
            input_lwe_dimension,
            &mut rsc.secret_random_generator,
        );
        let input_lwe_secret_key = LweSecretKey::from_container(
            small_lwe_sk
                .clone()
                .into_container()
                .iter()
                .copied()
                .map(|x| x as u64)
                .collect::<Vec<_>>(),
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<u128> =
            allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut rsc.secret_random_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();
        let output_lwe_dimension = output_lwe_secret_key.lwe_dimension();

        let mut bsk = LweMultiBitBootstrapKey::new(
            0u128,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            grouping_factor,
            ciphertext_modulus,
        );

        par_generate_lwe_multi_bit_bootstrap_key(
            &small_lwe_sk,
            &output_glwe_secret_key,
            &mut bsk,
            glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let d_bsk = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(&bsk, &stream);

        while msg != 0 {
            msg -= 1;
            for _ in 0..NB_TESTS {
                let input_plaintext_list =
                    PlaintextList::from_container(vec![msg * delta_64; number_of_messages]);

                let mut par_lwe_list = LweCiphertextList::new(
                    0u64,
                    input_lwe_dimension.to_lwe_size(),
                    LweCiphertextCount(number_of_messages),
                    ciphertext_modulus_64,
                );

                par_encrypt_lwe_ciphertext_list(
                    &input_lwe_secret_key,
                    &mut par_lwe_list,
                    &input_plaintext_list,
                    lwe_noise_distribution,
                    &mut rsc.encryption_random_generator,
                );

                assert!(check_encrypted_content_respects_mod(
                    &par_lwe_list,
                    ciphertext_modulus_64
                ));

                let d_lwe_ciphertext_in =
                    CudaLweCiphertextList::from_lwe_ciphertext_list(&par_lwe_list, &stream);
                let mut d_out_pbs_ct = CudaLweCiphertextList::new(
                    output_lwe_dimension,
                    d_lwe_ciphertext_in.lwe_ciphertext_count(),
                    ciphertext_modulus,
                    &stream,
                );
                let d_accumulator =
                    CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

                // We initialize it so cargo won't complain, but we don't use it internally
                let d_test_vector_indexes = unsafe { CudaVec::<u64>::new_async(1, &stream, 0) };

                let num_blocks = d_lwe_ciphertext_in.lwe_ciphertext_count().0;
                let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
                let lwe_indexes = lwe_indexes_usize
                    .iter()
                    .map(|&x| <usize as CastInto<u64>>::cast_into(x))
                    .collect_vec();
                let mut d_output_indexes =
                    unsafe { CudaVec::<u64>::new_async(num_blocks, &stream, 0) };
                let mut d_input_indexes =
                    unsafe { CudaVec::<u64>::new_async(num_blocks, &stream, 0) };
                unsafe {
                    d_input_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
                    d_output_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
                }

                cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext(
                    &d_lwe_ciphertext_in,
                    &mut d_out_pbs_ct,
                    &d_accumulator,
                    &d_test_vector_indexes,
                    &d_output_indexes,
                    &d_input_indexes,
                    &d_bsk,
                    &stream,
                );

                let out_pbs_ct_list = d_out_pbs_ct.to_lwe_ciphertext_list(&stream);
                assert!(check_encrypted_content_respects_mod(
                    &out_pbs_ct_list,
                    ciphertext_modulus
                ));

                let mut output_plaintext_list =
                    PlaintextList::from_container(vec![0u128; number_of_messages]);
                decrypt_lwe_ciphertext_list(
                    &output_lwe_secret_key,
                    &out_pbs_ct_list,
                    &mut output_plaintext_list,
                );

                output_plaintext_list.iter().for_each(|decrypted| {
                    let decoded = round_decode(*decrypted.0, delta) % msg_modulus.0 as u128;
                    assert_eq!(decoded, f(msg as u128));
                });
            }
        }
    }
}

#[test]
fn test_multibit_bootstrap_u128_with_squashing() {
    execute_multibit_bootstrap_u128(
        NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}
