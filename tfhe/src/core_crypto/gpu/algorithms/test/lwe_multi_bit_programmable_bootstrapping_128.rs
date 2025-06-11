use super::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext, CudaStreams,
};
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;
use crate::shortint::parameters::noise_squashing::NoiseSquashingMultiBitParameters;
use crate::shortint::parameters::{
    NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::MultiBitPBSParameters;
use itertools::Itertools;

fn execute_multibit_bootstrap_u128(
    squash_params: NoiseSquashingMultiBitParameters,
    input_params: MultiBitPBSParameters,
) {
    let input_lwe_dimension = input_params.lwe_dimension;
    let lwe_noise_distribution = input_params.lwe_noise_distribution;
    let glwe_noise_distribution = squash_params.glwe_noise_distribution;
    let ciphertext_modulus = squash_params.ciphertext_modulus;
    let ciphertext_modulus_64 = CiphertextModulus::new_native();
    let msg_modulus = input_params.message_modulus;
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
    let delta_64 = encoding_with_padding_64 / msg_modulus.0;
    let mut msg = msg_modulus.0;
    const NB_TESTS: usize = 10;
    let number_of_messages = 1;

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
            let plaintext = Plaintext(msg * delta_64);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus_64,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus_64
            ));

            let d_lwe_ciphertext_in =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);
            let mut d_out_pbs_ct = CudaLweCiphertextList::new(
                output_lwe_dimension,
                LweCiphertextCount(1),
                ciphertext_modulus,
                &stream,
            );
            let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let mut test_vector_indexes: Vec<u64> = vec![0; number_of_messages];
            for (i, ind) in test_vector_indexes.iter_mut().enumerate() {
                *ind = <usize as CastInto<u64>>::cast_into(i);
            }

            let mut d_test_vector_indexes =
                unsafe { CudaVec::<u64>::new_async(number_of_messages, &stream, 0) };
            unsafe { d_test_vector_indexes.copy_from_cpu_async(&test_vector_indexes, &stream, 0) };

            let num_blocks = d_lwe_ciphertext_in.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<u64>>::cast_into(x))
                .collect_vec();
            let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_blocks, &stream, 0) };
            let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_blocks, &stream, 0) };
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

            let out_pbs_ct = d_out_pbs_ct.into_lwe_ciphertext(&stream);
            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus.0 as u128;
            assert_eq!(decoded, f(msg as u128));
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
