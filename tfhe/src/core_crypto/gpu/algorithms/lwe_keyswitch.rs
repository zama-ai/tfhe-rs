#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    cleanup_cuda_keyswitch_gemm_64, cuda_closest_representable_64_async, keyswitch_async,
    keyswitch_async_gemm, scratch_cuda_keyswitch_gemm_64, CudaStreams,
};
use crate::core_crypto::prelude::UnsignedInteger;
use std::cmp::min;
use tfhe_cuda_backend::ffi;

#[allow(clippy::too_many_arguments)]
pub fn cuda_keyswitch_lwe_ciphertext<Scalar, KSKScalar>(
    lwe_keyswitch_key: &CudaLweKeyswitchKey<KSKScalar>,
    input_lwe_ciphertext: &CudaLweCiphertextList<Scalar>,
    output_lwe_ciphertext: &mut CudaLweCiphertextList<KSKScalar>,
    input_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    uses_trivial_indices: bool,
    streams: &CudaStreams,
    use_gemm_ks: bool,
) where
    Scalar: UnsignedInteger,
    KSKScalar: UnsignedInteger,
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

    // Modulus checks (mirroring keyswitch_lwe_ciphertext_native_mod_compatible)
    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        output_lwe_ciphertext
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU keyswitch currently only supports power of 2 moduli for the output ciphertext"
    );
    assert!(
        input_lwe_ciphertext
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU keyswitch currently only supports power of 2 moduli for the input ciphertext"
    );

    let mut ks_tmp_buffer: *mut ffi::c_void = std::ptr::null_mut();

    let num_lwes_to_ks = min(
        input_indexes.len,
        input_lwe_ciphertext.lwe_ciphertext_count().0,
    );

    assert_eq!(
        input_indexes.len, output_indexes.len,
        "The number of input and output indexes must be the same for LWE keyswitch"
    );

    unsafe {
        if use_gemm_ks {
            // Scratch allocations uses input LWE dtype for buffer size
            cuda_scratch_keyswitch_lwe_ciphertext::<Scalar>(
                streams,
                std::ptr::addr_of_mut!(ks_tmp_buffer),
                u32::try_from(lwe_keyswitch_key.input_key_lwe_size().to_lwe_dimension().0).unwrap(),
                u32::try_from(lwe_keyswitch_key.output_key_lwe_size().to_lwe_dimension().0)
                    .unwrap(),
                u32::try_from(num_lwes_to_ks).unwrap(),
                true,
            );

            // Gemm KS can KS with input LWE dtype Scalar to output LWE dtype KSKScalar
            keyswitch_async_gemm(
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
                u32::try_from(num_lwes_to_ks).unwrap(),
                ks_tmp_buffer,
                uses_trivial_indices,
            );

            cleanup_cuda_keyswitch::<Scalar>(streams, std::ptr::addr_of_mut!(ks_tmp_buffer), true);
        } else {
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
                u32::try_from(num_lwes_to_ks).unwrap(),
            );
        }
        streams.synchronize();
    }
}

/// # Safety
/// - `ks_tmp_buffer` must be a valid, writable pointer to a GPU pointer
/// - Must be allocated for the correct CUDA device
/// - Must not be aliased while this function runs
/// - `streams` must outlive the kernel execution
pub unsafe fn cuda_scratch_keyswitch_lwe_ciphertext<Scalar>(
    streams: &CudaStreams,
    ks_tmp_buffer: *mut *mut ffi::c_void,
    lwe_dimension_in: u32,
    lwe_dimension_out: u32,
    num_lwes: u32,
    allocate_gpu_memory: bool,
) where
    Scalar: UnsignedInteger,
{
    scratch_cuda_keyswitch_gemm_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        ks_tmp_buffer,
        lwe_dimension_in,
        lwe_dimension_out,
        num_lwes,
        allocate_gpu_memory,
    );
    streams.synchronize();
}

/// # Safety
/// - `ks_tmp_buffer` must be a valid, writable pointer to a GPU pointer
/// - Must be allocated for the correct CUDA device
/// - Must not be aliased while this function runs
/// - `streams` must outlive the kernel execution
pub unsafe fn cleanup_cuda_keyswitch<Scalar>(
    streams: &CudaStreams,
    ks_tmp_buffer: *mut *mut ffi::c_void,
    allocate_gpu_memory: bool,
) {
    cleanup_cuda_keyswitch_gemm_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        ks_tmp_buffer,
        allocate_gpu_memory,
    );
    streams.synchronize();
}

pub fn cuda_closest_representable<Scalar>(
    streams: &CudaStreams,
    input: &CudaVec<Scalar>,
    output: &mut CudaVec<Scalar>,
    base_log: u32,
    level_count: u32,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_closest_representable_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            input.as_c_ptr(0),
            output.as_mut_c_ptr(0),
            base_log,
            level_count,
        );
        streams.synchronize();
    }
}
