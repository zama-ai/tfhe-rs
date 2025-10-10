use super::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::{
    CudaLweBootstrapKey, CudaModulusSwitchNoiseReductionConfiguration,
};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{
    cuda_keyswitch_lwe_ciphertext, cuda_programmable_bootstrap_lwe_ciphertext, CudaStreams,
};
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;
use itertools::Itertools;

fn lwe_encrypt_pbs_decrypt<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: ClassicTestParams<Scalar>,
) {
    assert!(Scalar::BITS <= 64);

    let input_lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;
    let number_of_messages = 1;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();
    let output_lwe_dimension = output_lwe_secret_key.lwe_dimension();

    let mut bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        ciphertext_modulus
    ));

    let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, None, &stream);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
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

            let mut test_vector_indexes: Vec<Scalar> = vec![Scalar::ZERO; number_of_messages];
            for (i, ind) in test_vector_indexes.iter_mut().enumerate() {
                *ind = <usize as CastInto<Scalar>>::cast_into(i);
            }

            let mut d_test_vector_indexes =
                unsafe { CudaVec::<Scalar>::new_async(number_of_messages, &stream, 0) };
            unsafe { d_test_vector_indexes.copy_from_cpu_async(&test_vector_indexes, &stream, 0) };

            let num_blocks = d_lwe_ciphertext_in.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let mut d_output_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            let mut d_input_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
                d_output_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
            }

            cuda_programmable_bootstrap_lwe_ciphertext(
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

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

fn lwe_ks_encrypt_pbs_decrypt_compare_32_64<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + CastFrom<u32> + CastInto<u32>,
>(
    params: ClassicTestParams<Scalar>,
) {
    assert!(Scalar::BITS <= 64);

    let input_lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;
    let number_of_messages = 1;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    let lwe_noise_distribution_ksk_32 = match params.lwe_noise_distribution {
        DynamicDistribution::Gaussian(gaussian_lwe_noise_distribution) => {
            DynamicDistribution::<u32>::new_gaussian(gaussian_lwe_noise_distribution.standard_dev())
        }
        DynamicDistribution::TUniform(uniform_lwe_noise_distribution) => {
            DynamicDistribution::<u32>::new_t_uniform(
                uniform_lwe_noise_distribution.bound_log2() - 32,
            )
        }
    };

    // Create the LweSecretKey
    let intermediate_lwe_secret_key_32: LweSecretKeyOwned<u32> =
        allocate_and_generate_new_binary_lwe_secret_key(
            input_lwe_dimension,
            &mut rsc.secret_random_generator,
        ); // lwe_sk

    let glwe_sk_64: GlweSecretKeyOwned<Scalar> = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let big_lwe_sk_64 = glwe_sk_64.clone().into_lwe_secret_key();

    let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
        &big_lwe_sk_64,
        &intermediate_lwe_secret_key_32,
        params.ks_base_log,
        params.ks_level,
        lwe_noise_distribution_ksk_32,
        CiphertextModulus::<u32>::new_native(),
        &mut rsc.encryption_random_generator,
    );
    let d_ksk_big_to_small =
        CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

    let ciphertext_modulus_ks32 = CiphertextModulus::<u32>::new_native();

    let output_lwe_dimension = big_lwe_sk_64.lwe_dimension();

    let mut bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &intermediate_lwe_secret_key_32,
        &glwe_sk_64,
        &mut bsk,
        glwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        ciphertext_modulus
    ));

    let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, None, &stream);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk_64,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let d_lwe_ciphertext_in =
                CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

            let output_ks_ct: LweCiphertextOwned<u32> = LweCiphertext::new(
                0u32,
                intermediate_lwe_secret_key_32.lwe_dimension().to_lwe_size(),
                ciphertext_modulus_ks32,
            );
            let mut output_ks_ct_gpu =
                CudaLweCiphertextList::from_lwe_ciphertext(&output_ks_ct, &stream);

            let mut d_out_pbs_ct = CudaLweCiphertextList::new(
                output_lwe_dimension,
                LweCiphertextCount(1),
                ciphertext_modulus,
                &stream,
            );

            let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

            let test_vector_indexes: Vec<Scalar> = vec![Scalar::ZERO; number_of_messages];

            let mut d_test_vector_indexes =
                unsafe { CudaVec::<Scalar>::new_async(number_of_messages, &stream, 0) };
            unsafe { d_test_vector_indexes.copy_from_cpu_async(&test_vector_indexes, &stream, 0) };

            let num_blocks = d_lwe_ciphertext_in.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let mut d_output_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            let mut d_input_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
                d_output_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
            }

            cuda_keyswitch_lwe_ciphertext(
                &d_ksk_big_to_small,
                &d_lwe_ciphertext_in,
                &mut output_ks_ct_gpu,
                &d_input_indexes,
                &d_output_indexes,
                true,
                &stream,
                false,
            );

            cuda_programmable_bootstrap_lwe_ciphertext(
                &output_ks_ct_gpu,
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

            let decrypted = decrypt_lwe_ciphertext(&big_lwe_sk_64, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

fn lwe_encrypt_centered_ms_pbs_decrypt<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: ClassicTestParams<Scalar>,
) {
    assert!(Scalar::BITS <= 64);

    let input_lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;
    const NB_TESTS: usize = 10;
    let number_of_messages = 1;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();
    let output_lwe_dimension = output_lwe_secret_key.lwe_dimension();

    let h_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    // We force the centered modulus switch to test it
    let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
        &h_bsk,
        Some(CudaModulusSwitchNoiseReductionConfiguration::Centered),
        &stream,
    );

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
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

            let mut test_vector_indexes: Vec<Scalar> = vec![Scalar::ZERO; number_of_messages];
            for (i, ind) in test_vector_indexes.iter_mut().enumerate() {
                *ind = <usize as CastInto<Scalar>>::cast_into(i);
            }

            let mut d_test_vector_indexes =
                unsafe { CudaVec::<Scalar>::new_async(number_of_messages, &stream, 0) };
            unsafe { d_test_vector_indexes.copy_from_cpu_async(&test_vector_indexes, &stream, 0) };

            let num_blocks = d_lwe_ciphertext_in.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let mut d_output_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            let mut d_input_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            unsafe {
                d_input_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
                d_output_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0);
            }

            cuda_programmable_bootstrap_lwe_ciphertext(
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

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}
create_gpu_parameterized_test!(lwe_ks_encrypt_pbs_decrypt_compare_32_64);
create_gpu_parameterized_test!(lwe_encrypt_pbs_decrypt);
create_gpu_parameterized_test!(lwe_encrypt_centered_ms_pbs_decrypt);
