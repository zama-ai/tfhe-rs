use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{packing_keyswitch_list_async, CudaStreams};
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_async<Scalar>(
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

    packing_keyswitch_list_async(
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

pub fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_async(
            lwe_pksk,
            input_lwe_ciphertext_list,
            output_glwe_ciphertext,
            streams,
        );
    }
    streams.synchronize();
}
