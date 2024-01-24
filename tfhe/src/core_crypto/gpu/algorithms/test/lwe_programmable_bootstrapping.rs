use super::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{cuda_programmable_bootstrap_lwe_ciphertext, CudaDevice, CudaStream};
use itertools::Itertools;

fn lwe_encrypt_pbs_decrypt<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: ClassicTestParams<Scalar>,
) {
    assert!(Scalar::BITS <= 64);

    let input_lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.pbs_base_log;
    let decomp_level_count = params.pbs_level;

    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

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

    let accumulator = generate_accumulator(
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

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
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
            glwe_modular_std_dev,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&bsk, &stream);

        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_modular_std_dev,
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
                unsafe { stream.malloc_async::<Scalar>(number_of_messages as u32) };
            unsafe { stream.copy_to_gpu_async(&mut d_test_vector_indexes, &test_vector_indexes) };

            let num_blocks = d_lwe_ciphertext_in.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize: Vec<usize> = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let mut d_output_indexes = unsafe { stream.malloc_async::<Scalar>(num_blocks as u32) };
            let mut d_input_indexes = unsafe { stream.malloc_async::<Scalar>(num_blocks as u32) };
            unsafe {
                stream.copy_to_gpu_async(&mut d_output_indexes, &lwe_indexes);
                stream.copy_to_gpu_async(&mut d_input_indexes, &lwe_indexes);
            }

            cuda_programmable_bootstrap_lwe_ciphertext(
                &d_lwe_ciphertext_in,
                &mut d_out_pbs_ct,
                &d_accumulator,
                &d_test_vector_indexes,
                &d_output_indexes,
                &d_input_indexes,
                LweCiphertextCount(num_blocks),
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

create_gpu_parametrized_test!(lwe_encrypt_pbs_decrypt);

// DISCLAIMER: all parameters here are not guaranteed to be secure or yield correct computations
pub const TEST_PARAMS_4_BITS_NATIVE_U64: ClassicTestParams<u64> = ClassicTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(4.9982771e-11),
    glwe_modular_std_dev: StandardDev(8.6457178e-32),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
