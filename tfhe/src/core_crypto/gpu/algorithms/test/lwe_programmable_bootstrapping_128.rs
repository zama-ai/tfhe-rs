pub(crate) use crate::core_crypto::algorithms::test::gen_keys_or_get_from_cache_if_enabled;

use crate::core_crypto::algorithms::test::{
    FftBootstrapKeys, FftTestParams, TestResources, FFT_U128_PARAMS, FFT_U32_PARAMS, FFT128_U128_GPU_PARAMS,
};
use crate::core_crypto::fft_impl::common::FourierBootstrapKey;
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{cuda_programmable_bootstrap_lwe_ciphertext, CudaStreams};

use crate::core_crypto::keycache::KeyCacheAccess;
use crate::core_crypto::prelude::*;
use dyn_stack::{GlobalPodBuffer, PodStack};
use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn generate_keys<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: FftTestParams<Scalar>,
    rsc: &mut TestResources,
) -> FftBootstrapKeys<Scalar> {
    // Generate an LweSecretKey with binary coefficients
    let small_lwe_sk =
        LweSecretKey::generate_new_binary(params.lwe_dimension, &mut rsc.secret_random_generator);

    // Generate a GlweSecretKey with binary coefficients
    let glwe_sk = GlweSecretKey::generate_new_binary(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );

    // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    FftBootstrapKeys {
        small_lwe_sk,
        big_lwe_sk,
        bsk,
    }
}

pub fn execute_bootstrap_u128<Scalar, K>(params: FftTestParams<Scalar>)
where
    Scalar: Numeric
        + UnsignedTorus
        + CastFrom<usize>
        + CastInto<usize>
        + Send
        + Sync
        + Serialize
        + DeserializeOwned,
    K: FourierBootstrapKey<Scalar>,
    FftTestParams<Scalar>: KeyCacheAccess<Keys = FftBootstrapKeys<Scalar>>,
{
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ciphertext_modulus = params.ciphertext_modulus;

    let mut rsc = TestResources::new();

    let fft = K::new_fft(polynomial_size);

    let mut keys_gen = |params| generate_keys(params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(params, &mut keys_gen);
    let (std_bootstrapping_key, small_lwe_sk, big_lwe_sk) =
        (keys.bsk, keys.small_lwe_sk, keys.big_lwe_sk);
    let output_lwe_dimension = big_lwe_sk.lwe_dimension();
    let mut cnt = 0;
    let mut level_matrix_cnt = 0;
    for Ggsw in std_bootstrapping_key.iter() {
        for ggsw_level_matrix in Ggsw.iter() {
            for glwe_ciphertext in ggsw_level_matrix.as_glwe_list().iter() {
                for polynomial in glwe_ciphertext.as_polynomial_list().iter() {
                    for coef in polynomial.iter() {
                        cnt += 1;
                    }
                }
            }
        }
    }
    // println!("std_bootstrapping_key: {:?}", std_bootstrapping_key);
    // println!("std_bootstrapping_key: {:?}", std_bootstrapping_key.iter().len());
    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = K::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    println!(
        "decomposition_base_log: {:?}",
        std_bootstrapping_key.decomposition_base_log()
    );
    println!("cnt: {:?}", cnt);
    println!("rust transforming standard bsk");
    fourier_bsk.fill_with_forward_fourier(
        &std_bootstrapping_key,
        &fft,
        PodStack::new(&mut GlobalPodBuffer::new(
            K::fill_with_forward_fourier_scratch(&fft).unwrap(),
        )),
    );

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(&std_bootstrapping_key, &stream);

    // Our 4 bits message space
    let message_modulus: Scalar = Scalar::ONE << 4;

    // Our input message
    let input_message: Scalar = 3usize.cast_into();
    let number_of_messages = 1;
    // Delta used to encode 4 bits of message + a bit of padding on Scalar
    let delta: Scalar = (Scalar::ONE << (Scalar::BITS - 1)) / message_modulus;

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let f = |x: Scalar| x;
    let accumulator: GlweCiphertextOwned<Scalar> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut pbs_ct: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
        Scalar::ZERO,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    println!("Computing PBS...");

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
    let mut d_output_indexes = unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
    let mut d_input_indexes = unsafe { CudaVec::<Scalar>::new_async(num_blocks, &stream, 0) };
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
        LweCiphertextCount(num_blocks),
        &d_bsk,
        &stream,
    );

    pbs_ct = d_out_pbs_ct.into_lwe_ciphertext(&stream);
    // fourier_bsk.bootstrap(
    //     &mut pbs_ct,
    //     &lwe_ciphertext_in,
    //     &accumulator,
    //     &fft,
    //     PodStack::new(&mut GlobalPodBuffer::new(
    //         K::bootstrap_scratch(
    //             std_bootstrapping_key.glwe_size(),
    //             std_bootstrapping_key.polynomial_size(),
    //             &fft,
    //         )
    //         .unwrap(),
    //     )),
    // );

    // Decrypt the PBS result
    let pbs_plaintext: Plaintext<Scalar> = decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_ct);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
    // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    // Round and remove our encoding
    let pbs_result: Scalar = signed_decomposer.closest_representable(pbs_plaintext.0) / delta;

    println!("Checking result...");
    assert_eq!(f(input_message), pbs_result);
}

#[test]
fn test_bootstrap_u128() {
    execute_bootstrap_u128::<u128, Fourier128LweBootstrapKeyOwned>(FFT128_U128_GPU_PARAMS);
}
