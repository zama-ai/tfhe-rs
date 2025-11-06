use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{keyswitch_async, scratch_cuda_keyswitch_64, CudaStreams};
use crate::core_crypto::prelude::UnsignedInteger;
use std::cmp::min;
use tfhe_cuda_backend::bindings::cleanup_cuda_keyswitch_64;
use tfhe_cuda_backend::ffi;

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
    uses_trivial_indices: bool,
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

    let mut ks_tmp_buffer: *mut ffi::c_void = std::ptr::null_mut();

    let num_lwes_to_ks = min(
        input_indexes.len,
        input_lwe_ciphertext.lwe_ciphertext_count().0,
    );

    assert_eq!(input_indexes.len, output_indexes.len);

    cuda_scratch_keyswitch_lwe_ciphertext_async::<Scalar>(
        streams,
        std::ptr::addr_of_mut!(ks_tmp_buffer),
        lwe_keyswitch_key.input_key_lwe_size().to_lwe_dimension().0 as u32,
        lwe_keyswitch_key.output_key_lwe_size().to_lwe_dimension().0 as u32,
        num_lwes_to_ks as u32,
        true,
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
        num_lwes_to_ks as u32,
        ks_tmp_buffer,
        uses_trivial_indices,
    );

    cleanup_cuda_keyswitch_async::<Scalar>(streams, std::ptr::addr_of_mut!(ks_tmp_buffer), true);
}

pub fn cuda_keyswitch_lwe_ciphertext<Scalar>(
    lwe_keyswitch_key: &CudaLweKeyswitchKey<Scalar>,
    input_lwe_ciphertext: &CudaLweCiphertextList<Scalar>,
    output_lwe_ciphertext: &mut CudaLweCiphertextList<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    uses_trivial_indices: bool,
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
            uses_trivial_indices,
            streams,
        );
    }
    streams.synchronize();
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronized
pub unsafe fn cuda_scratch_keyswitch_lwe_ciphertext_async<Scalar>(
    streams: &CudaStreams,
    ks_tmp_buffer: *mut *mut ffi::c_void,
    lwe_dimension_in: u32,
    lwe_dimension_out: u32,
    num_lwes: u32,
    allocate_gpu_memory: bool,
) where
    Scalar: UnsignedInteger,
{
    scratch_cuda_keyswitch_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        ks_tmp_buffer,
        lwe_dimension_in,
        lwe_dimension_out,
        num_lwes,
        allocate_gpu_memory,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronized
pub unsafe fn cleanup_cuda_keyswitch_async<Scalar>(
    streams: &CudaStreams,
    ks_tmp_buffer: *mut *mut ffi::c_void,
    allocate_gpu_memory: bool,
) {
    cleanup_cuda_keyswitch_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        ks_tmp_buffer,
        allocate_gpu_memory,
    );
}
