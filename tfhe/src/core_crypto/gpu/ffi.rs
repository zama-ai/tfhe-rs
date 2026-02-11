use super::{CudaStreams, PBSMSNoiseReductionType};
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaModulusSwitchNoiseReductionConfiguration;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweCiphertextCount, LweDimension, PolynomialSize, UnsignedInteger,
};
use std::any::{Any, TypeId};
use std::ffi::c_void;
use tfhe_cuda_backend::bindings::*;
use tfhe_cuda_backend::ffi;

/// Programmable bootstrap on a vector of LWE ciphertexts
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn programmable_bootstrap<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_out_indexes: &CudaVec<T>,
    test_vector: &CudaVec<T>,
    test_vector_indexes: &CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    lwe_in_indexes: &CudaVec<T>,
    bootstrapping_key: &CudaVec<f64>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    num_samples: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let num_many_lut = 1u32;
    let lut_stride = 0u32;
    let mut pbs_buffer: *mut i8 = std::ptr::null_mut();

    // Initializes as NoReduction and change variables later if otherwise
    let noise_reduction_type = ms_noise_reduction_configuration
        .map_or(PBSMSNoiseReductionType::NoReduction, |_config| {
            PBSMSNoiseReductionType::Centered
        });

    scratch_cuda_programmable_bootstrap_64_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(pbs_buffer),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        level.0 as u32,
        num_samples,
        true,
        noise_reduction_type as u32,
    );

    cuda_programmable_bootstrap_64_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_out_indexes.as_c_ptr(0),
        test_vector.as_c_ptr(0),
        test_vector_indexes.as_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        lwe_in_indexes.as_c_ptr(0),
        bootstrapping_key.as_c_ptr(0),
        pbs_buffer,
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        base_log.0 as u32,
        level.0 as u32,
        num_samples,
        num_many_lut,
        lut_stride,
    );

    cleanup_cuda_programmable_bootstrap_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(pbs_buffer),
    );
}

#[allow(clippy::too_many_arguments)]
pub fn get_programmable_bootstrap_size_on_gpu(
    streams: &CudaStreams,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    level: DecompositionLevelCount,
    num_samples: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
    let noise_reduction_type = ms_noise_reduction_configuration
        .map_or(PBSMSNoiseReductionType::NoReduction, |_config| {
            PBSMSNoiseReductionType::Centered
        });
    let size_tracker = unsafe {
        scratch_cuda_programmable_bootstrap_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            num_samples,
            false,
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_programmable_bootstrap_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
        );
    }
    size_tracker
}

/// Programmable bootstrap on a vector of 128 bit LWE ciphertexts
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn programmable_bootstrap_128<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    test_vector: &CudaVec<T>,
    lwe_array_in: &CudaVec<u64>,
    bootstrapping_key: &CudaVec<f64>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    num_samples: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let mut pbs_buffer: *mut i8 = std::ptr::null_mut();

    // Initializes as NoReduction and change variables later if otherwise
    let noise_reduction_type = ms_noise_reduction_configuration
        .map_or(PBSMSNoiseReductionType::NoReduction, |_config| {
            PBSMSNoiseReductionType::Centered
        });

    scratch_cuda_programmable_bootstrap_128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(pbs_buffer),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        level.0 as u32,
        num_samples,
        true,
        noise_reduction_type as u32,
    );

    cuda_programmable_bootstrap_128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        test_vector.as_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        bootstrapping_key.as_c_ptr(0),
        pbs_buffer,
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        base_log.0 as u32,
        level.0 as u32,
        num_samples,
    );

    cleanup_cuda_programmable_bootstrap_128(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(pbs_buffer),
    );
}

/// Programmable multi-bit bootstrap on a vector of LWE ciphertexts
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn programmable_bootstrap_multi_bit<T: UnsignedInteger, B: Any + UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<B>,
    output_indexes: &CudaVec<T>,
    test_vector: &CudaVec<B>,
    test_vector_indexes: &CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    input_indexes: &CudaVec<T>,
    bootstrapping_key: &CudaVec<B>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    num_samples: u32,
) {
    let num_many_lut = 1u32;
    let lut_stride = 0u32;
    let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
    if TypeId::of::<B>() == TypeId::of::<u128>() {
        scratch_cuda_multi_bit_programmable_bootstrap_128_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            num_samples,
            true,
        );
        cuda_multi_bit_programmable_bootstrap_128_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            output_indexes.as_c_ptr(0),
            test_vector.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            input_indexes.as_c_ptr(0),
            bootstrapping_key.as_c_ptr(0),
            pbs_buffer,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            grouping_factor.0 as u32,
            base_log.0 as u32,
            level.0 as u32,
            num_samples,
            num_many_lut,
            lut_stride,
        );
        cleanup_cuda_multi_bit_programmable_bootstrap_128(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
        );
    } else if TypeId::of::<B>() == TypeId::of::<u64>() {
        scratch_cuda_multi_bit_programmable_bootstrap_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            num_samples,
            true,
        );
        cuda_multi_bit_programmable_bootstrap_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            output_indexes.as_c_ptr(0),
            test_vector.as_c_ptr(0),
            test_vector_indexes.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            input_indexes.as_c_ptr(0),
            bootstrapping_key.as_c_ptr(0),
            pbs_buffer,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            grouping_factor.0 as u32,
            base_log.0 as u32,
            level.0 as u32,
            num_samples,
            num_many_lut,
            lut_stride,
        );
        cleanup_cuda_multi_bit_programmable_bootstrap_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
        );
    } else {
        panic!("Unsupported torus size")
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_programmable_bootstrap_multi_bit_size_on_gpu(
    streams: &CudaStreams,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    level: DecompositionLevelCount,
    num_samples: u32,
) -> u64 {
    let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_multi_bit_programmable_bootstrap_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            num_samples,
            false,
        )
    };
    unsafe {
        cleanup_cuda_multi_bit_programmable_bootstrap_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(pbs_buffer),
        );
    }
    size_tracker
}

/// Keyswitch on a vector of LWE ciphertexts using the GEMM batch KS approach
///
/// Allocates scratch memory, runs the keyswitch, and cleans up.
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn keyswitch_gemm<T: UnsignedInteger, KST: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<KST>,
    lwe_out_indexes: &CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    lwe_in_indexes: &CudaVec<T>,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    keyswitch_key: &CudaVec<KST>,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    num_samples: u32,
    uses_trivial_indices: bool,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());

    let mut ks_tmp_buffer: *mut ffi::c_void = std::ptr::null_mut();

    if TypeId::of::<KST>() == TypeId::of::<u32>() {
        scratch_cuda_keyswitch_gemm_64_32_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(ks_tmp_buffer),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            num_samples,
            true,
        );
        cuda_keyswitch_gemm_64_32_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            lwe_out_indexes.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            lwe_in_indexes.as_c_ptr(0),
            keyswitch_key.as_c_ptr(0),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            base_log.0 as u32,
            l_gadget.0 as u32,
            num_samples,
            ks_tmp_buffer,
            uses_trivial_indices,
        );
        cleanup_cuda_keyswitch_gemm_64_32(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(ks_tmp_buffer),
            true,
        );
    } else if TypeId::of::<KST>() == TypeId::of::<u64>() {
        scratch_cuda_keyswitch_gemm_64_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(ks_tmp_buffer),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            num_samples,
            true,
        );
        cuda_keyswitch_gemm_64_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            lwe_out_indexes.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            lwe_in_indexes.as_c_ptr(0),
            keyswitch_key.as_c_ptr(0),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            base_log.0 as u32,
            l_gadget.0 as u32,
            num_samples,
            ks_tmp_buffer,
            uses_trivial_indices,
        );
        cleanup_cuda_keyswitch_gemm_64_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(ks_tmp_buffer),
            true,
        );
    } else {
        panic!("Unknown LWE GEMM KS dtype of size {}B", size_of::<KST>());
    }
}

/// Keyswitch on a vector of LWE ciphertexts. Better for small batches of LWEs
/// (up to 128 LWEs on H100, up to 64 on L40, up to 16 on 4090)
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn keyswitch_async<T: UnsignedInteger, KT: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<KT>,
    lwe_out_indexes: &CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    lwe_in_indexes: &CudaVec<T>,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    keyswitch_key: &CudaVec<KT>,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());

    if TypeId::of::<KT>() == TypeId::of::<u32>() {
        cuda_keyswitch_lwe_ciphertext_vector_64_32_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            lwe_out_indexes.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            lwe_in_indexes.as_c_ptr(0),
            keyswitch_key.as_c_ptr(0),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            base_log.0 as u32,
            l_gadget.0 as u32,
            num_samples,
        );
    } else if TypeId::of::<KT>() == TypeId::of::<u64>() {
        cuda_keyswitch_lwe_ciphertext_vector_64_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            lwe_out_indexes.as_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            lwe_in_indexes.as_c_ptr(0),
            keyswitch_key.as_c_ptr(0),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            base_log.0 as u32,
            l_gadget.0 as u32,
            num_samples,
        );
    } else {
        panic!("Unknown LWE KS dtype of size {}B", size_of::<KT>());
    }
}
/// Convert keyswitch key
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn convert_lwe_keyswitch_key_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    dest: &mut CudaVec<T>,
    src: &[T],
) {
    dest.copy_from_cpu_multi_gpu_async(src, streams);
}

/// Applies packing keyswitch on a vector of LWE ciphertexts
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn packing_keyswitch_list_64<T: UnsignedInteger>(
    streams: &CudaStreams,
    glwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    packing_keyswitch_key: &CudaVec<T>,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    num_lwes: LweCiphertextCount,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());

    let mut fp_ks_buffer: *mut i8 = std::ptr::null_mut();
    scratch_cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(fp_ks_buffer),
        input_lwe_dimension.0 as u32,
        output_glwe_dimension.0 as u32,
        output_polynomial_size.0 as u32,
        num_lwes.0 as u32,
        true,
    );
    cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        glwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        packing_keyswitch_key.as_c_ptr(0),
        fp_ks_buffer,
        input_lwe_dimension.0 as u32,
        output_glwe_dimension.0 as u32,
        output_polynomial_size.0 as u32,
        base_log.0 as u32,
        l_gadget.0 as u32,
        num_lwes.0 as u32,
    );
    cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(fp_ks_buffer),
        true,
    );
}

/// Applies packing keyswitch on a vector of 128-bit LWE ciphertexts
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn packing_keyswitch_list_128<T: UnsignedInteger>(
    streams: &CudaStreams,
    glwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    packing_keyswitch_key: &CudaVec<T>,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    num_lwes: LweCiphertextCount,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u128>());
    let mut fp_ks_buffer: *mut i8 = std::ptr::null_mut();
    scratch_cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(fp_ks_buffer),
        input_lwe_dimension.0 as u32,
        output_glwe_dimension.0 as u32,
        output_polynomial_size.0 as u32,
        num_lwes.0 as u32,
        true,
    );
    cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        glwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        packing_keyswitch_key.as_c_ptr(0),
        fp_ks_buffer,
        input_lwe_dimension.0 as u32,
        output_glwe_dimension.0 as u32,
        output_polynomial_size.0 as u32,
        base_log.0 as u32,
        l_gadget.0 as u32,
        num_lwes.0 as u32,
    );
    cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_128(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        std::ptr::addr_of_mut!(fp_ks_buffer),
        true,
    );
}

/// Convert programmable bootstrap key
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn convert_lwe_programmable_bootstrap_key_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    dest: &mut CudaVec<f64>,
    src: &[T],
    input_lwe_dim: LweDimension,
    glwe_dim: GlweDimension,
    l_gadget: DecompositionLevelCount,
    polynomial_size: PolynomialSize,
) {
    for (i, &stream_ptr) in streams.ptr.iter().enumerate() {
        if size_of::<T>() == 16 {
            cuda_convert_lwe_programmable_bootstrap_key_128_async(
                stream_ptr,
                streams.gpu_indexes[i].get(),
                dest.as_mut_c_ptr(i as u32),
                src.as_ptr().cast(),
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
            );
        } else if size_of::<T>() == 8 {
            cuda_convert_lwe_programmable_bootstrap_key_64_async(
                stream_ptr,
                streams.gpu_indexes[i].get(),
                dest.as_mut_c_ptr(i as u32),
                src.as_ptr().cast(),
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
            );
        } else {
            panic!("Unsupported torus size for bsk conversion")
        }
    }
}

/// Convert multi-bit programmable bootstrap key
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn convert_lwe_multi_bit_programmable_bootstrap_key_async<T: Any + UnsignedInteger>(
    streams: &CudaStreams,
    dest: &mut CudaVec<T>,
    src: &[T],
    input_lwe_dim: LweDimension,
    glwe_dim: GlweDimension,
    l_gadget: DecompositionLevelCount,
    polynomial_size: PolynomialSize,
    grouping_factor: LweBskGroupingFactor,
) {
    let size = std::mem::size_of_val(src);
    for (i, &stream_ptr) in streams.ptr.iter().enumerate() {
        assert_eq!(dest.len() * std::mem::size_of::<T>(), size);

        if TypeId::of::<T>() == TypeId::of::<u128>() {
            cuda_convert_lwe_multi_bit_programmable_bootstrap_key_128_async(
                stream_ptr,
                streams.gpu_indexes[i].get(),
                dest.as_mut_c_ptr(i as u32),
                src.as_ptr().cast(),
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
                grouping_factor.0 as u32,
            );
        } else if TypeId::of::<T>() == TypeId::of::<u64>() {
            cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64_async(
                stream_ptr,
                streams.gpu_indexes[i].get(),
                dest.as_mut_c_ptr(i as u32),
                src.as_ptr().cast(),
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
                grouping_factor.0 as u32,
            );
        } else {
            panic!("Unsupported torus size for bsk conversion")
        }
    }
}

/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn extract_lwe_samples_from_glwe_ciphertext_list_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    glwe_array_in: &CudaVec<T>,
    nth_array: &CudaVec<u32>,
    num_nths: u32,
    lwe_per_glwe: u32,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) {
    if size_of::<T>() == 16 {
        cuda_glwe_sample_extract_128_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            glwe_array_in.as_c_ptr(0),
            nth_array.as_c_ptr(0).cast::<u32>(),
            num_nths,
            lwe_per_glwe,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
        );
    } else if size_of::<T>() == 8 {
        cuda_glwe_sample_extract_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            lwe_array_out.as_mut_c_ptr(0),
            glwe_array_in.as_c_ptr(0),
            nth_array.as_c_ptr(0).cast::<u32>(),
            num_nths,
            lwe_per_glwe,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
        );
    } else {
        panic!("Unsupported torus size for glwe sample extraction")
    }
}

/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn cuda_modulus_switch_ciphertext_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    log_modulus: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_modulus_switch_inplace_64_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_out.len() as u32,
        log_modulus,
    );
}

pub fn cuda_modulus_switch_ciphertext<Scalar>(
    output_lwe_ciphertext: &mut CudaVec<Scalar>,
    log_modulus: u32,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_modulus_switch_ciphertext_async(streams, output_lwe_ciphertext, log_modulus);
    }
    streams.synchronize();
}

/// Addition of a vector of LWE ciphertexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn add_lwe_ciphertext_vector_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in_1: &CudaVec<T>,
    lwe_array_in_2: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    let mut output_degrees_vec: Vec<u64> = vec![0; num_samples as usize];
    let mut output_noise_levels_vec: Vec<u64> = vec![0; num_samples as usize];
    let mut input_1_degrees_vec = output_degrees_vec.clone();
    let mut input_1_noise_levels_vec = output_noise_levels_vec.clone();
    let mut input_2_degrees_vec = output_degrees_vec.clone();
    let mut input_2_noise_levels_vec = output_noise_levels_vec.clone();
    let mut lwe_array_out_data = CudaRadixCiphertextFFI {
        ptr: lwe_array_out.as_mut_c_ptr(0),
        degrees: output_degrees_vec.as_mut_ptr(),
        noise_levels: output_noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: num_samples,
        max_num_radix_blocks: num_samples,
        lwe_dimension: lwe_dimension.0 as u32,
    };
    let lwe_array_in_1_data = CudaRadixCiphertextFFI {
        ptr: lwe_array_in_1.get_mut_c_ptr(0),
        degrees: input_1_degrees_vec.as_mut_ptr(),
        noise_levels: input_1_noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: num_samples,
        max_num_radix_blocks: num_samples,
        lwe_dimension: lwe_dimension.0 as u32,
    };
    let lwe_array_in_2_data = CudaRadixCiphertextFFI {
        ptr: lwe_array_in_2.get_mut_c_ptr(0),
        degrees: input_2_degrees_vec.as_mut_ptr(),
        noise_levels: input_2_noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: num_samples,
        max_num_radix_blocks: num_samples,
        lwe_dimension: lwe_dimension.0 as u32,
    };
    cuda_add_lwe_ciphertext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        &raw mut lwe_array_out_data,
        &raw const lwe_array_in_1_data,
        &raw const lwe_array_in_2_data,
    );
}

/// Assigned addition of a vector of LWE ciphertexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn add_lwe_ciphertext_vector_assign_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    let mut output_degrees_vec: Vec<u64> = vec![0; num_samples as usize];
    let mut output_noise_levels_vec: Vec<u64> = vec![0; num_samples as usize];
    let mut input_degrees_vec = output_degrees_vec.clone();
    let mut input_noise_levels_vec = output_noise_levels_vec.clone();
    let mut lwe_array_out_data = CudaRadixCiphertextFFI {
        ptr: lwe_array_out.as_mut_c_ptr(0),
        degrees: output_degrees_vec.as_mut_ptr(),
        noise_levels: output_noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: num_samples,
        max_num_radix_blocks: num_samples,
        lwe_dimension: lwe_dimension.0 as u32,
    };
    let lwe_array_in_data = CudaRadixCiphertextFFI {
        ptr: lwe_array_in.get_mut_c_ptr(0),
        degrees: input_degrees_vec.as_mut_ptr(),
        noise_levels: input_noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: num_samples,
        max_num_radix_blocks: num_samples,
        lwe_dimension: lwe_dimension.0 as u32,
    };
    cuda_add_lwe_ciphertext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        &raw mut lwe_array_out_data,
        &raw const lwe_array_out_data,
        &raw const lwe_array_in_data,
    );
}

/// Addition of a vector of LWE ciphertexts with a vector of plaintexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn add_lwe_ciphertext_vector_plaintext_vector_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    plaintext_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        plaintext_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Addition of a vector of LWE ciphertexts with a plaintext scalar
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn add_lwe_ciphertext_vector_plaintext_scalar_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    plaintext_in: u64,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_add_lwe_ciphertext_vector_plaintext_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        plaintext_in,
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Assigned addition of a vector of LWE ciphertexts with a vector of plaintexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn add_lwe_ciphertext_vector_plaintext_vector_assign_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    plaintext_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_out.as_c_ptr(0),
        plaintext_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Negation of a vector of LWE ciphertexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn negate_lwe_ciphertext_vector_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_negate_lwe_ciphertext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Assigned negation of a vector of LWE ciphertexts
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn negate_lwe_ciphertext_vector_assign_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_negate_lwe_ciphertext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_out.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Multiplication of a vector of LWEs with a vector of cleartexts (assigned)
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn mult_lwe_ciphertext_vector_cleartext_vector_assign_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array: &mut CudaVec<T>,
    cleartext_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array.as_mut_c_ptr(0),
        lwe_array.as_c_ptr(0),
        cleartext_array_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// Multiplication of a vector of LWEs with a vector of cleartexts.
///
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior./// required
pub unsafe fn mult_lwe_ciphertext_vector_cleartext_vector<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    lwe_array_in: &CudaVec<T>,
    cleartext_array_in: &CudaVec<T>,
    lwe_dimension: LweDimension,
    num_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u64>());
    cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        lwe_array_out.as_mut_c_ptr(0),
        lwe_array_in.as_c_ptr(0),
        cleartext_array_in.as_c_ptr(0),
        lwe_dimension.0 as u32,
        num_samples,
    );
}

/// forward fourier transform for complex f128 as integer
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn fourier_transform_forward_as_integer_f128_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    re0: &mut [f64],
    re1: &mut [f64],
    im0: &mut [f64],
    im1: &mut [f64],
    standard: &[T],
    fft_size: u32,
    number_of_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u128>());
    cuda_fourier_transform_forward_as_integer_f128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        re0.as_mut_ptr().cast::<c_void>(),
        re1.as_mut_ptr().cast::<c_void>(),
        im0.as_mut_ptr().cast::<c_void>(),
        im1.as_mut_ptr().cast::<c_void>(),
        standard.as_ptr().cast::<c_void>(),
        fft_size,
        number_of_samples,
    );
}

/// forward fourier transform for complex f128 as torus
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn fourier_transform_forward_as_torus_f128_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    re0: &mut [f64],
    re1: &mut [f64],
    im0: &mut [f64],
    im1: &mut [f64],
    standard: &[T],
    fft_size: u32,
    number_of_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u128>());
    cuda_fourier_transform_forward_as_torus_f128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        re0.as_mut_ptr().cast::<c_void>(),
        re1.as_mut_ptr().cast::<c_void>(),
        im0.as_mut_ptr().cast::<c_void>(),
        im1.as_mut_ptr().cast::<c_void>(),
        standard.as_ptr().cast::<c_void>(),
        fft_size,
        number_of_samples,
    );
}

/// backward fourier transform for complex f128 as torus
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
#[allow(clippy::too_many_arguments)]
pub unsafe fn fourier_transform_backward_as_torus_f128_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    standard: &mut [T],
    re0: &[f64],
    re1: &[f64],
    im0: &[f64],
    im1: &[f64],
    fft_size: u32,
    number_of_samples: u32,
) {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<u128>());
    cuda_fourier_transform_backward_as_torus_f128_async(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        standard.as_mut_ptr().cast::<c_void>(),
        re0.as_ptr().cast::<c_void>(),
        re1.as_ptr().cast::<c_void>(),
        im0.as_ptr().cast::<c_void>(),
        im1.as_ptr().cast::<c_void>(),
        fft_size,
        number_of_samples,
    );
}

pub fn get_packing_keyswitch_list_64_size_on_gpu(
    streams: &CudaStreams,
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    num_lwes: LweCiphertextCount,
) -> u64 {
    let mut fp_ks_buffer: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(fp_ks_buffer),
            input_lwe_dimension.0 as u32,
            output_glwe_dimension.0 as u32,
            output_polynomial_size.0 as u32,
            num_lwes.0 as u32,
            false,
        )
    };
    unsafe {
        cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            std::ptr::addr_of_mut!(fp_ks_buffer),
            false,
        );
    }
    size_tracker
}
