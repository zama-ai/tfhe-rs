use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweCiphertextCount, LweDimension, Numeric, PolynomialSize, UnsignedInteger,
};
use crate::integer::gpu::PBSType;
use crate::shortint::{CarryModulus, MessageModulus};
use tfhe_cuda_backend::bindings::*;

pub unsafe fn lwe_expand_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_compact_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: LweCiphertextCount,
    max_ciphertext_per_bin: u32,
) {
    cuda_lwe_expand_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_compact_array_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples.0 as u32,
        max_ciphertext_per_bin,
    );
}

pub unsafe fn expand_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_compact_array_in: &CudaVec<T>,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    num_samples: LweCiphertextCount,
    max_ciphertext_per_bin: u32,
) {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    scratch_cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        (glwe_dimension.0 * polynomial_size.0) as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_samples.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        0,
        true,
    );
    cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        lwe_array_out.as_mut_c_ptr(0),
        lwe_compact_array_in.as_c_ptr(0),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}
