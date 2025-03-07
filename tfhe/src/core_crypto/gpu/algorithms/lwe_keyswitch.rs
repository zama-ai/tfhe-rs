use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{keyswitch_async, CudaStreams};
use crate::core_crypto::prelude::UnsignedInteger;

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_keyswitch_lwe_ciphertext_async<Scalar>(
    lwe_keyswitch_key: &CudaLweKeyswitchKey<Scalar>,
    input_lwe_ciphertext: &CudaLweCiphertextList<Scalar>,
    output_lwe_ciphertext: &mut CudaLweCiphertextList<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_size().to_lwe_dimension()
            == input_lwe_ciphertext.lwe_dimension(),
        "Mismatched input LweDimension. \
        LweKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.input_key_lwe_size().to_lwe_dimension(),
        input_lwe_ciphertext.lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_size().to_lwe_dimension()
            == output_lwe_ciphertext.lwe_dimension(),
        "Mismatched output LweDimension. \
        LweKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.output_key_lwe_size().to_lwe_dimension(),
        output_lwe_ciphertext.lwe_dimension(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_keyswitch_key.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_keyswitch_key.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_lwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input lwe pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_lwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_lwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output lwe pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_lwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_indexes.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input indexes pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_indexes.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_indexes.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output indexes pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_indexes.gpu_index(0).get(),
    );

    keyswitch_async(
        streams,
        &mut output_lwe_ciphertext.0.d_vec,
        output_indexes,
        &input_lwe_ciphertext.0.d_vec,
        input_indexes,
        lwe_keyswitch_key.input_key_lwe_size().to_lwe_dimension(),
        lwe_keyswitch_key.output_key_lwe_size().to_lwe_dimension(),
        &lwe_keyswitch_key.d_vec,
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
        input_lwe_ciphertext.lwe_ciphertext_count().0 as u32,
    );
}

pub fn cuda_keyswitch_lwe_ciphertext<Scalar>(
    lwe_keyswitch_key: &CudaLweKeyswitchKey<Scalar>,
    input_lwe_ciphertext: &CudaLweCiphertextList<Scalar>,
    output_lwe_ciphertext: &mut CudaLweCiphertextList<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_keyswitch_lwe_ciphertext_async(
            lwe_keyswitch_key,
            input_lwe_ciphertext,
            output_lwe_ciphertext,
            input_indexes,
            output_indexes,
            streams,
        );
    }
    streams.synchronize();
}
