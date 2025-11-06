use super::*;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{cuda_keyswitch_lwe_ciphertext, CudaStreams};
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;
use itertools::Itertools;
use rand::seq::SliceRandom;
use rand::thread_rng;

fn lwe_encrypt_ks_decrypt_custom_mod<Scalar: UnsignedTorus + CastFrom<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    base_lwe_encrypt_ks_decrypt_custom_mod(
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        message_modulus_log,
        encoding_with_padding,
        glwe_dimension,
        polynomial_size,
        ks_decomp_base_log,
        ks_decomp_level_count,
    );
}

fn lwe_encrypt_ks_decrypt_custom_mod_mb<Scalar: UnsignedTorus + CastFrom<usize>>(
    params: &MultiBitTestParams<Scalar>,
) {
    let lwe_dimension = params.input_lwe_dimension;
    let lwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0f64));
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.decomp_base_log;
    let ks_decomp_level_count = params.decomp_level_count;

    base_lwe_encrypt_ks_decrypt_custom_mod(
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        message_modulus_log,
        encoding_with_padding,
        glwe_dimension,
        polynomial_size,
        ks_decomp_base_log,
        ks_decomp_level_count,
    );
}

#[allow(clippy::too_many_arguments)]
fn base_lwe_encrypt_ks_decrypt_custom_mod<Scalar: UnsignedTorus + CastFrom<usize>>(
    lwe_dimension: LweDimension,
    lwe_noise_distribution: DynamicDistribution<Scalar>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    message_modulus_log: MessageModulusLog,
    encoding_with_padding: Scalar,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_decomp_base_log: DecompositionBaseLog,
    ks_decomp_level_count: DecompositionLevelCount,
) {
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(0));

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

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

    let d_ksk_big_to_small =
        CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for test_idx in 0..NB_TESTS {
            let num_blocks = test_idx * test_idx * 3 + 1;

            let plaintext_list = (0..num_blocks)
                .map(|i| (Scalar::cast_from(i) % msg_modulus) * delta)
                .collect_vec();

            let plaintext_list = PlaintextList::from_container(plaintext_list);

            let mut input_ct_list = LweCiphertextList::new(
                Scalar::ZERO,
                big_lwe_sk.lwe_dimension().to_lwe_size(),
                LweCiphertextCount(num_blocks),
                ciphertext_modulus,
            );
            encrypt_lwe_ciphertext_list(
                &big_lwe_sk,
                &mut input_ct_list,
                &plaintext_list,
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );
            let input_ct_list_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&input_ct_list, &stream);

            let output_ct_list = LweCiphertextList::new(
                Scalar::ZERO,
                ksk_big_to_small.output_key_lwe_dimension().to_lwe_size(),
                input_ct_list.lwe_ciphertext_count(),
                ksk_big_to_small.ciphertext_modulus(),
            );
            let mut output_ct_list_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_ct_list, &stream);
            let mut output_ct_list_gpu_gemm =
                CudaLweCiphertextList::from_lwe_ciphertext_list(&output_ct_list, &stream);

            assert!(check_encrypted_content_respects_mod(
                &input_ct_list,
                ciphertext_modulus
            ));

            let use_trivial_indexes = test_idx % 2 == 0;

            let num_blocks_to_ks = if use_trivial_indexes {
                if test_idx % 4 == 0 {
                    num_blocks
                } else {
                    num_blocks / 2
                }
            } else {
                num_blocks
            };
            let lwe_indexes_usize = (0..num_blocks).collect_vec();
            let mut lwe_indexes = lwe_indexes_usize.clone();

            let mut lwe_indexes_out = lwe_indexes.clone();

            if !use_trivial_indexes {
                lwe_indexes.shuffle(&mut thread_rng());
                lwe_indexes_out.shuffle(&mut thread_rng());
            }

            let h_lwe_indexes: Vec<Scalar> = lwe_indexes
                .iter()
                .take(num_blocks_to_ks)
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let h_lwe_indexes_out: Vec<Scalar> = lwe_indexes_out
                .iter()
                .take(num_blocks_to_ks)
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();

            let mut d_input_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks_to_ks, &stream, 0) };
            let mut d_output_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks_to_ks, &stream, 0) };
            unsafe { d_input_indexes.copy_from_cpu_async(&h_lwe_indexes, &stream, 0) };
            unsafe { d_output_indexes.copy_from_cpu_async(&h_lwe_indexes_out, &stream, 0) };

            cuda_keyswitch_lwe_ciphertext(
                &d_ksk_big_to_small,
                &input_ct_list_gpu,
                &mut output_ct_list_gpu,
                &d_input_indexes,
                &d_output_indexes,
                use_trivial_indexes,
                &stream,
                false,
            );

            cuda_keyswitch_lwe_ciphertext(
                &d_ksk_big_to_small,
                &input_ct_list_gpu,
                &mut output_ct_list_gpu_gemm,
                &d_input_indexes,
                &d_output_indexes,
                use_trivial_indexes,
                &stream,
                true,
            );

            // Fill in the expected output: only the LWEs corresponding to output indices
            // will be non-zero. The test checks that the others remain 0
            let mut ref_vec = vec![Scalar::ZERO; num_blocks];
            for i in 0..num_blocks_to_ks {
                ref_vec[lwe_indexes_out[i]] =
                    round_decode(*plaintext_list.get(lwe_indexes[i]).0, delta);
            }

            assert_eq!(output_ct_list_gpu.lwe_ciphertext_count().0, num_blocks);
            // The output has `n_blocks` LWEs but only some are actually set - those
            // that correspond to output indices. We loop over all LWEs in the output buffer
            let output_ct_list_cpu = output_ct_list_gpu_gemm.to_lwe_ciphertext_list(&stream);
            output_ct_list_gpu
                .to_lwe_ciphertext_list(&stream)
                .iter()
                .zip(0..num_blocks)
                .for_each(|(lwe_ct_out, i)| {
                    assert!(check_encrypted_content_respects_mod(
                        &lwe_ct_out,
                        ciphertext_modulus
                    ));

                    let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &lwe_ct_out);

                    let lwe_ct_out_gemm = output_ct_list_cpu.get(i);
                    let decrypted_gemm = decrypt_lwe_ciphertext(&lwe_sk, &lwe_ct_out_gemm);

                    let decoded = round_decode(decrypted.0, delta) % msg_modulus;
                    let decoded_gemm = round_decode(decrypted_gemm.0, delta) % msg_modulus;

                    assert_eq!(ref_vec[i], decoded);
                    assert_eq!(ref_vec[i], decoded_gemm);
                });
        }
    }
}

create_gpu_parameterized_test!(lwe_encrypt_ks_decrypt_custom_mod);
create_gpu_multi_bit_parameterized_test!(lwe_encrypt_ks_decrypt_custom_mod_mb);
