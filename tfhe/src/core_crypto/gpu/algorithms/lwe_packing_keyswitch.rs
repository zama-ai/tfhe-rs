use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{
    packing_keyswitch_list_128_async, packing_keyswitch_list_64_async, CudaStreams,
};
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64_async<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let input_lwe_dimension = input_lwe_ciphertext_list.lwe_dimension();
    let output_glwe_dimension = output_glwe_ciphertext.glwe_dimension();
    let output_polynomial_size = output_glwe_ciphertext.polynomial_size();
    assert_eq!(
        streams.gpu_indexes[0],
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_glwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_glwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_pksk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first pksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_pksk.d_vec.gpu_index(0).get(),
    );

    packing_keyswitch_list_64_async(
        streams,
        &mut output_glwe_ciphertext.0.d_vec,
        &input_lwe_ciphertext_list.0.d_vec,
        input_lwe_dimension,
        output_glwe_dimension,
        output_polynomial_size,
        &lwe_pksk.d_vec,
        lwe_pksk.decomposition_base_log(),
        lwe_pksk.decomposition_level_count(),
        input_lwe_ciphertext_list.lwe_ciphertext_count(),
    );
}

pub fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64_async(
            lwe_pksk,
            input_lwe_ciphertext_list,
            output_glwe_ciphertext,
            streams,
        );
    }
    streams.synchronize();
}
/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128_async<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let input_lwe_dimension = input_lwe_ciphertext_list.lwe_dimension();
    let output_glwe_dimension = output_glwe_ciphertext.glwe_dimension();
    let output_polynomial_size = output_glwe_ciphertext.polynomial_size();
    assert_eq!(
        streams.gpu_indexes[0],
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_glwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_glwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_pksk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first pksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_pksk.d_vec.gpu_index(0).get(),
    );

    packing_keyswitch_list_128_async(
        streams,
        &mut output_glwe_ciphertext.0.d_vec,
        &input_lwe_ciphertext_list.0.d_vec,
        input_lwe_dimension,
        output_glwe_dimension,
        output_polynomial_size,
        &lwe_pksk.d_vec,
        lwe_pksk.decomposition_base_log(),
        lwe_pksk.decomposition_level_count(),
        input_lwe_ciphertext_list.lwe_ciphertext_count(),
    );
}

pub fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128_async(
            lwe_pksk,
            input_lwe_ciphertext_list,
            output_glwe_ciphertext,
            streams,
        );
    }
    streams.synchronize();
}
