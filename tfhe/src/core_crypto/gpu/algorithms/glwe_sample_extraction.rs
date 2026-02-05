#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{extract_lwe_samples_from_glwe_ciphertext_list_async, CudaStreams};
use crate::core_crypto::prelude::{MonomialDegree, UnsignedTorus};
use itertools::Itertools;

/// For each [`GLWE Ciphertext`] (`CudaGlweCiphertextList`) given as input, extract the nth
/// coefficient from its body as an [`LWE ciphertext`](`CudaLweCiphertextList`). This variant is
/// GPU-accelerated.
pub fn cuda_extract_lwe_samples_from_glwe_ciphertext_list<Scalar>(
    input_glwe_list: &CudaGlweCiphertextList<Scalar>,
    output_lwe_list: &mut CudaLweCiphertextList<Scalar>,
    vec_nth: &[MonomialDegree],
    lwe_per_glwe: u32,
    streams: &CudaStreams,
) where
    Scalar: UnsignedTorus,
{
    let in_lwe_dim = input_glwe_list
        .glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe_list.polynomial_size());

    let out_lwe_dim = output_lwe_list.lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    // lwe_per_glwe LWEs will be extracted per GLWE ciphertext, thus we need to have enough indexes
    assert_eq!(
        vec_nth.len(),
        input_glwe_list.glwe_ciphertext_count().0 * lwe_per_glwe as usize,
        "Mismatch between number of nths and number of GLWEs provided.",
    );

    assert_eq!(
        input_glwe_list.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe_list.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus()
    );
    assert!(
        input_glwe_list
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU sample extraction currently only supports power of 2 moduli"
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_glwe_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input_glwe_list pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_glwe_list.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_lwe_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output_lwe_list pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_lwe_list.0.d_vec.gpu_index(0).get(),
    );

    let nth_array: Vec<u32> = vec_nth
        .iter()
        .map(|x| u32::try_from(x.0).unwrap())
        .collect_vec();
    let gpu_indexes = &streams.gpu_indexes;
    unsafe {
        let d_nth_array = CudaVec::from_cpu_async(&nth_array, streams, gpu_indexes[0].get());
        extract_lwe_samples_from_glwe_ciphertext_list_async(
            streams,
            &mut output_lwe_list.0.d_vec,
            &input_glwe_list.0.d_vec,
            &d_nth_array,
            u32::try_from(vec_nth.len()).unwrap(),
            lwe_per_glwe,
            input_glwe_list.glwe_dimension(),
            input_glwe_list.polynomial_size(),
        );
        streams.synchronize();
    }
}
