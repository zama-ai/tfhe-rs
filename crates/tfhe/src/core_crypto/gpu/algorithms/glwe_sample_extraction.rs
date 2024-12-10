use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{extract_lwe_samples_from_glwe_ciphertext_list_async, CudaStreams};
use crate::core_crypto::prelude::{MonomialDegree, UnsignedTorus};
use itertools::Itertools;

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_extract_lwe_samples_from_glwe_ciphertext_list_async<Scalar>(
    input_glwe_list: &CudaGlweCiphertextList<Scalar>,
    output_lwe_list: &mut CudaLweCiphertextList<Scalar>,
    vec_nth: &[MonomialDegree],
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

    assert_eq!(
        vec_nth.len(),
        input_glwe_list.glwe_ciphertext_count().0 * input_glwe_list.polynomial_size().0,
        "Mismatch between number of nths and number of GLWEs provided.",
    );

    assert_eq!(
        input_glwe_list.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe_list.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus()
    );

    let nth_array: Vec<u32> = vec_nth.iter().map(|x| x.0 as u32).collect_vec();
    let gpu_indexes = &streams.gpu_indexes;
    unsafe {
        let d_nth_array = CudaVec::from_cpu_async(&nth_array, streams, gpu_indexes[0].0);
        extract_lwe_samples_from_glwe_ciphertext_list_async(
            streams,
            &mut output_lwe_list.0.d_vec,
            &input_glwe_list.0.d_vec,
            &d_nth_array,
            vec_nth.len() as u32,
            input_glwe_list.glwe_dimension(),
            input_glwe_list.polynomial_size(),
        );
    }
}

/// For each [`GLWE Ciphertext`] (`CudaGlweCiphertextList`) given as input, extract the nth
/// coefficient from its body as an [`LWE ciphertext`](`CudaLweCiphertextList`). This variant is
/// GPU-accelerated.
pub fn cuda_extract_lwe_samples_from_glwe_ciphertext_list<Scalar>(
    input_glwe_list: &CudaGlweCiphertextList<Scalar>,
    output_lwe_list: &mut CudaLweCiphertextList<Scalar>,
    vec_nth: &[MonomialDegree],
    streams: &CudaStreams,
) where
    Scalar: UnsignedTorus,
{
    unsafe {
        cuda_extract_lwe_samples_from_glwe_ciphertext_list_async(
            input_glwe_list,
            output_lwe_list,
            vec_nth,
            streams,
        );
    }
    streams.synchronize();
}
