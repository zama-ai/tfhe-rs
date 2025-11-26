use super::*;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{cuda_keyswitch_lwe_ciphertext, CudaStreams};
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;
use itertools::Itertools;

fn lwe_encrypt_ks_decrypt_custom_mod_common<
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<KSKScalar> + CastFrom<KSKScalar>,
    KSKScalar: UnsignedTorus,
>(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_noise_distribution: DynamicDistribution<Scalar>,
    ks_decomp_base_log: DecompositionBaseLog,
    ks_decomp_level_count: DecompositionLevelCount,
    message_modulus_log: MessageModulusLog,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    let lwe_noise_distribution_32 = DynamicDistribution::<KSKScalar>::new_gaussian_from_std_dev(
        StandardDev(0.000002226459789930014),
    );

    let ciphertext_modulus_32 = CiphertextModulus::<KSKScalar>::new_native();
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
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
        lwe_noise_distribution_32,
        ciphertext_modulus_32,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_encrypted_content_respects_mod(
        &ksk_big_to_small,
        ciphertext_modulus_32
    ));

    let d_ksk_big_to_small =
        CudaLweKeyswitchKey::from_lwe_keyswitch_key(&ksk_big_to_small, &stream);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let ct = allocate_and_encrypt_new_lwe_ciphertext(
                &big_lwe_sk,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let d_ct = CudaLweCiphertextList::from_lwe_ciphertext(&ct, &stream);
            let mut d_output_ct = CudaLweCiphertextList::new(
                ksk_big_to_small.output_key_lwe_dimension(),
                LweCiphertextCount(1),
                ciphertext_modulus_32,
                &stream,
            );
            let num_blocks = d_ct.0.lwe_ciphertext_count.0;
            let lwe_indexes_usize = (0..num_blocks).collect_vec();
            let lwe_indexes = lwe_indexes_usize
                .iter()
                .map(|&x| <usize as CastInto<Scalar>>::cast_into(x))
                .collect_vec();
            let mut d_input_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            let mut d_output_indexes =
                unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
            unsafe { d_input_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0) };
            unsafe { d_output_indexes.copy_from_cpu_async(&lwe_indexes, &stream, 0) };

            cuda_keyswitch_lwe_ciphertext(
                &d_ksk_big_to_small,
                &d_ct,
                &mut d_output_ct,
                &d_input_indexes,
                &d_output_indexes,
                &stream,
            );

            let output_ct = d_output_ct.into_lwe_ciphertext(&stream);

            assert!(check_encrypted_content_respects_mod(
                &output_ct,
                ciphertext_modulus_32
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

            let decoded = round_decode(decrypted.0.cast_into(), delta) % msg_modulus;

            assert_eq!(msg, decoded);
        }
    }
}
fn lwe_encrypt_ks_decrypt_custom_mod<
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<u64> + CastFrom<u64>,
>(
    params: ClassicTestParams<Scalar>,
) {
    lwe_encrypt_ks_decrypt_custom_mod_common::<Scalar, u64>(
        params.lwe_dimension,
        params.glwe_dimension,
        params.polynomial_size,
        params.lwe_noise_distribution,
        params.ks_base_log,
        params.ks_level,
        params.message_modulus_log,
        params.ciphertext_modulus,
    );
}

fn lwe_encrypt_ks_decrypt_custom_mod_ks32<
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<u32> + CastFrom<u32>,
>(
    params: &MultiBitTestKS32Params<Scalar>,
) {
    lwe_encrypt_ks_decrypt_custom_mod_common::<Scalar, u32>(
        params.input_lwe_dimension,
        params.glwe_dimension,
        params.polynomial_size,
        params.lwe_noise_distribution,
        params.decomp_base_log,
        params.decomp_level_count,
        params.message_modulus_log,
        params.ciphertext_modulus,
    );
}

create_gpu_parameterized_test!(lwe_encrypt_ks_decrypt_custom_mod);
create_gpu_multi_bit_ks32_parameterized_test!(lwe_encrypt_ks_decrypt_custom_mod_ks32);
