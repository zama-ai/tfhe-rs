pub mod ciphertext;
pub mod client_key;
pub mod key_switching_key;
pub mod list_compression;
pub mod noise_squashing;
pub mod server_key;
#[cfg(feature = "zk-pok")]
pub mod zk;

use crate::core_crypto::gpu::lwe_bootstrap_key::{
    prepare_cuda_ms_noise_reduction_key_ffi, CudaModulusSwitchNoiseReductionKey,
};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::slice::{CudaSlice, CudaSliceMut};
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweDimension, Numeric, PolynomialSize, UnsignedInteger,
};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, KsType};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::server_key::ScalarMultiplier;
use crate::integer::{ClientKey, RadixClientKey};
use crate::prelude::CastInto;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::ModulusSwitchType;
use crate::shortint::{CarryModulus, MessageModulus};
use itertools::Itertools;
pub use server_key::CudaServerKey;
use std::any::TypeId;
use std::cmp::min;
use tfhe_cuda_backend::bindings::*;
use tfhe_cuda_backend::cuda_bind::*;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum BitOpType {
    And = 0,
    Or = 1,
    Xor = 2,
    ScalarAnd = 3,
    ScalarOr = 4,
    ScalarXor = 5,
}

#[allow(dead_code)]
#[repr(u32)]
pub enum PBSType {
    MultiBit = 0,
    Classical = 1,
}

#[repr(u32)]
pub enum ShiftRotateType {
    LeftShift = 0,
    RightShift = 1,
    LeftRotate = 2,
    RightRotate = 3,
}

#[repr(u32)]
pub enum ComparisonType {
    EQ = 0,
    NE = 1,
    GT = 2,
    GE = 3,
    LT = 4,
    LE = 5,
    MAX = 6,
    MIN = 7,
}

// If we build the Vec<u64> inside prepare_cuda_radix_ffi
// the data gets dropped before the call to the Cuda function,
// and we get memory errors, hence why the reconstruction of
// degrees and noise levels vecs is not done here
fn prepare_cuda_radix_ffi(
    input: &CudaRadixCiphertext,
    degrees_vec: &mut Vec<u64>,
    noise_levels_vec: &mut Vec<u64>,
) -> CudaRadixCiphertextFFI {
    CudaRadixCiphertextFFI {
        ptr: input.d_blocks.0.d_vec.get_mut_c_ptr(0),
        degrees: degrees_vec.as_mut_ptr(),
        noise_levels: noise_levels_vec.as_mut_ptr(),
        num_radix_blocks: input.d_blocks.0.lwe_ciphertext_count.0 as u32,
        max_num_radix_blocks: input.d_blocks.0.lwe_ciphertext_count.0 as u32,
        lwe_dimension: input.d_blocks.0.lwe_dimension.0 as u32,
    }
}

fn prepare_cuda_radix_ffi_from_slice<T: UnsignedInteger>(
    input: &CudaSlice<T>,
    degrees_vec: &mut Vec<u64>,
    noise_levels_vec: &mut Vec<u64>,
    num_radix_blocks: u32,
    lwe_dimension: u32,
) -> CudaRadixCiphertextFFI {
    CudaRadixCiphertextFFI {
        ptr: input.ptrs[0].cast_mut(),
        degrees: degrees_vec.as_mut_ptr(),
        noise_levels: noise_levels_vec.as_mut_ptr(),
        num_radix_blocks,
        max_num_radix_blocks: num_radix_blocks,
        lwe_dimension,
    }
}

fn prepare_cuda_radix_ffi_from_slice_mut<T: UnsignedInteger>(
    input: &CudaSliceMut<T>,
    degrees_vec: &mut Vec<u64>,
    noise_levels_vec: &mut Vec<u64>,
    num_radix_blocks: u32,
    lwe_dimension: u32,
) -> CudaRadixCiphertextFFI {
    CudaRadixCiphertextFFI {
        ptr: input.ptrs[0],
        degrees: degrees_vec.as_mut_ptr(),
        noise_levels: noise_levels_vec.as_mut_ptr(),
        num_radix_blocks,
        max_num_radix_blocks: num_radix_blocks,
        lwe_dimension,
    }
}

unsafe fn update_noise_degree(
    radix_ct: &mut CudaRadixCiphertext,
    cuda_ffi_radix_ct: &CudaRadixCiphertextFFI,
) {
    radix_ct
        .info
        .blocks
        .iter_mut()
        .enumerate()
        .for_each(|(i, b)| {
            b.degree = Degree(*cuda_ffi_radix_ct.degrees.wrapping_add(i));
            b.noise_level = NoiseLevel(*cuda_ffi_radix_ct.noise_levels.wrapping_add(i));
        });
}
pub fn gen_keys_gpu<P>(parameters_set: P, streams: &CudaStreams) -> (ClientKey, CudaServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let shortint_parameters_set: crate::shortint::parameters::ShortintParameterSet =
        parameters_set.try_into().unwrap();

    let is_wopbs_only_params = shortint_parameters_set.wopbs_only();

    // TODO
    // Manually manage the wopbs only case as a workaround pending wopbs rework
    // WOPBS used for PBS have no known failure probability at the moment, putting 1.0 for now
    let shortint_parameters_set = if is_wopbs_only_params {
        let wopbs_params = shortint_parameters_set.wopbs_parameters().unwrap();
        let pbs_params = crate::shortint::parameters::ClassicPBSParameters {
            lwe_dimension: wopbs_params.lwe_dimension,
            glwe_dimension: wopbs_params.glwe_dimension,
            polynomial_size: wopbs_params.polynomial_size,
            lwe_noise_distribution: wopbs_params.lwe_noise_distribution,
            glwe_noise_distribution: wopbs_params.glwe_noise_distribution,
            pbs_base_log: wopbs_params.pbs_base_log,
            pbs_level: wopbs_params.pbs_level,
            ks_base_log: wopbs_params.ks_base_log,
            ks_level: wopbs_params.ks_level,
            message_modulus: wopbs_params.message_modulus,
            carry_modulus: wopbs_params.carry_modulus,
            max_noise_level: crate::shortint::parameters::MaxNoiseLevel::from_msg_carry_modulus(
                wopbs_params.message_modulus,
                wopbs_params.carry_modulus,
            ),
            log2_p_fail: 1.0,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
            modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
        };

        crate::shortint::parameters::ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
            pbs_params,
            wopbs_params,
        ))
        .unwrap()
    } else {
        shortint_parameters_set
    };

    let gen_keys_inner = |parameters_set, streams: &CudaStreams| {
        let cks = ClientKey::new(parameters_set);
        let sks = CudaServerKey::new(&cks, streams);

        (cks, sks)
    };

    // #[cfg(any(test, feature = "internal-keycache"))]
    // {
    //     if is_wopbs_only_params {
    //         // TODO
    //         // Keycache is broken for the wopbs only case, so generate keys instead
    //         gen_keys_inner(shortint_parameters_set)
    //     } else {
    //         keycache::KEY_CACHE.get_from_params(shortint_parameters_set.pbs_parameters().
    // unwrap())     }
    // }
    // #[cfg(all(not(test), not(feature = "internal-keycache")))]
    // {
    gen_keys_inner(shortint_parameters_set, streams)
    // }
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys_gpu], this returns a [RadixClientKey]
///
/// ```rust
/// use tfhe::core_crypto::gpu::CudaStreams;
/// use tfhe::core_crypto::gpu::vec::GpuIndex;
/// use tfhe::integer::gpu::gen_keys_radix_gpu;
/// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
///
/// let gpu_index = 0;
/// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
/// // generate the client key and the server key:
/// let num_blocks = 4;
/// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
/// ```
pub fn gen_keys_radix_gpu<P>(
    parameters_set: P,
    num_blocks: usize,
    streams: &CudaStreams,
) -> (RadixClientKey, CudaServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let (cks, sks) = gen_keys_gpu(parameters_set, streams);

    (RadixClientKey::from((cks, num_blocks)), sks)
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn scalar_addition_integer_radix_assign_async<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array: &mut CudaRadixCiphertext,
    scalar_input: &CudaVec<T>,
    h_scalar_input: &[T],
    num_scalars: u32,
    message_modulus: u32,
    carry_modulus: u32,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        scalar_input.gpu_index(0),
        "GPU error: first stream is on GPU {}, first scalar pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        scalar_input.gpu_index(0).get(),
    );
    let mut lwe_array_degrees = lwe_array.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut lwe_array_noise_levels = lwe_array
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_lwe_array = prepare_cuda_radix_ffi(
        lwe_array,
        &mut lwe_array_degrees,
        &mut lwe_array_noise_levels,
    );
    cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_lwe_array,
        scalar_input.as_c_ptr(0),
        h_scalar_input.as_ptr().cast::<std::ffi::c_void>(),
        num_scalars,
        message_modulus,
        carry_modulus,
    );
    update_noise_degree(lwe_array, &cuda_ffi_lwe_array);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_mul_integer_radix_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lwe_array: &mut CudaRadixCiphertext,
    decomposed_scalar: &[T],
    has_at_least_one_set: &[T],
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    num_scalars: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lwe array pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = lwe_array.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut lwe_array_degrees = lwe_array.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut lwe_array_noise_levels = lwe_array
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_lwe_array = prepare_cuda_radix_ffi(
        lwe_array,
        &mut lwe_array_degrees,
        &mut lwe_array_noise_levels,
    );
    let msg_bits = message_modulus.0.ilog2() as usize;
    let num_blocks = lwe_array.d_blocks.lwe_ciphertext_count().0 as u32;
    let num_ciphertext_bits = msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == T::ONE)
        .count() as u32;

    scratch_cuda_integer_scalar_mul_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        lwe_array.d_blocks.0.lwe_ciphertext_count.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        num_scalar_bits,
        true,
        allocate_ms_noise_array,
    );

    cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_lwe_array,
        decomposed_scalar.as_ptr().cast::<u64>(),
        has_at_least_one_set.as_ptr().cast::<u64>(),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        polynomial_size.0 as u32,
        message_modulus.0 as u32,
        num_scalars,
    );

    cleanup_cuda_integer_radix_scalar_mul(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(lwe_array, &cuda_ffi_lwe_array);
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_mul_integer_radix_kb_size_on_gpu<T: UnsignedInteger>(
    streams: &CudaStreams,
    decomposed_scalar: &[T],
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let msg_bits = message_modulus.0.ilog2() as usize;
    let num_ciphertext_bits = msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == T::ONE)
        .count() as u32;

    let size_tracker = unsafe {
        scratch_cuda_integer_scalar_mul_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            num_scalar_bits,
            false,
            allocate_ms_noise_array,
        )
    };

    unsafe {
        cleanup_cuda_integer_radix_scalar_mul(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_div_integer_radix_kb_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    rhs: Scalar,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    pbs_type: PBSType,
    is_divisor_power_of_two: bool,
    log2_divisor_exceeds_threshold: bool,
    multiplier_exceeds_threshold: bool,
    ilog2_divisor: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64
where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let msg_bits = message_modulus.0.ilog2() as usize;
    let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let size_tracker = unsafe {
        scratch_cuda_integer_unsigned_scalar_div_radix_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            is_divisor_power_of_two,
            log2_divisor_exceeds_threshold,
            multiplier_exceeds_threshold,
            num_scalar_bits,
            ilog2_divisor,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_unsigned_scalar_div_radix_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        )
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
pub fn get_signed_scalar_div_integer_radix_kb_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    rhs: Scalar,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    pbs_type: PBSType,
    is_absolute_divisor_one: bool,
    is_divisor_negative: bool,
    l_exceed_threshold: bool,
    is_power_of_two: bool,
    multiplier_is_small: bool,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64
where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let msg_bits = message_modulus.0.ilog2() as usize;
    let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let size_tracker = unsafe {
        scratch_cuda_integer_signed_scalar_div_radix_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            num_scalar_bits,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            is_absolute_divisor_one,
            is_divisor_negative,
            l_exceed_threshold,
            is_power_of_two,
            multiplier_is_small,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_signed_scalar_div_radix_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        )
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn compress_integer_radix_async<
    InputTorus: UnsignedInteger,
    OutputTorus: UnsignedInteger,
>(
    streams: &CudaStreams,
    glwe_array_out: &mut CudaVec<OutputTorus>,
    lwe_array_in: &CudaVec<InputTorus>,
    fp_keyswitch_key: &CudaVec<OutputTorus>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    lwe_per_glwe: u32,
    storage_log_modulus: u32,
    num_blocks: u32,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        glwe_array_out.gpu_index(0),
        "GPU error: first stream is on GPU {}, first glwe output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        glwe_array_out.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array_in.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array_in.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        fp_keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first fp_ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        fp_keyswitch_key.gpu_index(0).get(),
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    if TypeId::of::<OutputTorus>() == TypeId::of::<u64>() {
        // 64 bits
        scratch_cuda_integer_compress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            lwe_per_glwe,
            storage_log_modulus,
            true,
        );

        cuda_integer_compress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            glwe_array_out.as_mut_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            fp_keyswitch_key.ptr.as_ptr(),
            num_blocks,
            mem_ptr,
        );

        cleanup_cuda_integer_compress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    } else if TypeId::of::<OutputTorus>() == TypeId::of::<u128>() {
        // 128 bits
        scratch_cuda_integer_compress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            lwe_per_glwe,
            storage_log_modulus,
            true,
        );

        cuda_integer_compress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            glwe_array_out.as_mut_c_ptr(0),
            lwe_array_in.as_c_ptr(0),
            fp_keyswitch_key.ptr.as_ptr(),
            num_blocks,
            mem_ptr,
        );

        cleanup_cuda_integer_compress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_compression_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    lwe_per_glwe: u32,
    storage_log_modulus: u32,
    num_blocks: u32,
) -> u64 {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_compress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            lwe_per_glwe,
            storage_log_modulus,
            false,
        )
    };

    unsafe {
        cleanup_cuda_integer_compress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn decompress_integer_radix_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaVec<T>,
    glwe_in: &CudaVec<T>,
    bootstrapping_key: &CudaVec<B>,
    bodies_count: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    encryption_glwe_dimension: GlweDimension,
    encryption_polynomial_size: PolynomialSize,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    storage_log_modulus: u32,
    vec_indexes: &[u32],
    num_lwes: u32,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array_out.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array_out.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        glwe_in.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        glwe_in.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    if TypeId::of::<T>() == TypeId::of::<u64>() {
        // 64 bits
        scratch_cuda_integer_decompress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            encryption_glwe_dimension.0 as u32,
            encryption_polynomial_size.0 as u32,
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            num_lwes,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            storage_log_modulus,
            bodies_count,
            true,
            false,
        );

        cuda_integer_decompress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            lwe_array_out.as_mut_c_ptr(0),
            glwe_in.as_c_ptr(0),
            vec_indexes.as_ptr(),
            vec_indexes.len() as u32,
            bootstrapping_key.ptr.as_ptr(),
            mem_ptr,
        );

        cleanup_cuda_integer_decompress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    } else if TypeId::of::<T>() == TypeId::of::<u128>() {
        // 128 bits
        scratch_cuda_integer_decompress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            encryption_glwe_dimension.0 as u32,
            encryption_polynomial_size.0 as u32,
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            num_lwes,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            storage_log_modulus,
            bodies_count,
            true,
            false,
        );

        cuda_integer_decompress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            lwe_array_out.as_mut_c_ptr(0),
            glwe_in.as_c_ptr(0),
            vec_indexes.as_ptr(),
            vec_indexes.len() as u32,
            bootstrapping_key.ptr.as_ptr(),
            mem_ptr,
        );

        cleanup_cuda_integer_decompress_radix_ciphertext_128(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_decompression_size_on_gpu(
    streams: &CudaStreams,
    bodies_count: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    encryption_glwe_dimension: GlweDimension,
    encryption_polynomial_size: PolynomialSize,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    storage_log_modulus: u32,
    num_lwes: u32,
) -> u64 {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_decompress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            encryption_glwe_dimension.0 as u32,
            encryption_polynomial_size.0 as u32,
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            num_lwes,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            storage_log_modulus,
            bodies_count,
            false,
            false,
        )
    };

    unsafe {
        cleanup_cuda_integer_decompress_radix_ciphertext_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_add_integer_radix_assign_async(
    streams: &CudaStreams,
    radix_lwe_left: &mut CudaRadixCiphertext,
    radix_lwe_right: &CudaRadixCiphertext,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    let mut radix_lwe_left_degrees = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_left_noise_levels = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_lwe_left,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    // Here even though the input is not modified, data is passed as mutable.
    // This avoids having to create two structs for the CudaRadixCiphertext pointers,
    // one const and the other mutable.
    // Having two structs on the Cuda side complicates things as we need to be sure we pass the
    // Const structure as input instead of the mutable structure, which leads to complicated
    // data manipulation on the C++ side to change mutability of data.
    let mut radix_lwe_right_degrees = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_right_noise_levels = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_right = prepare_cuda_radix_ffi(
        radix_lwe_right,
        &mut radix_lwe_right_degrees,
        &mut radix_lwe_right_noise_levels,
    );
    cuda_add_lwe_ciphertext_vector_64(
        streams.ptr[0],
        streams.gpu_indexes[0].get(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
    );
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_mul_integer_radix_kb_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_left: &mut CudaRadixCiphertext,
    is_boolean_left: bool,
    radix_lwe_right: &CudaRadixCiphertext,
    is_boolean_right: bool,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_left
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_left_noise_levels = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_lwe_left,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    // Here even though the input is not modified, data is passed as mutable.
    // This avoids having to create two structs for the CudaRadixCiphertext pointers,
    // one const and the other mutable.
    // Having two structs on the Cuda side complicates things as we need to be sure we pass the
    // Const structure as input instead of the mutable structure, which leads to complicated
    // data manipulation on the C++ side to change mutability of data.
    let mut radix_lwe_right_degrees = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_right_noise_levels = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_right = prepare_cuda_radix_ffi(
        radix_lwe_right,
        &mut radix_lwe_right_degrees,
        &mut radix_lwe_right_noise_levels,
    );
    scratch_cuda_integer_mult_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        is_boolean_left,
        is_boolean_right,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        glwe_dimension.0 as u32,
        lwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        pbs_base_log.0 as u32,
        pbs_level.0 as u32,
        ks_base_log.0 as u32,
        ks_level.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_mult_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_left,
        is_boolean_left,
        &raw const cuda_ffi_radix_lwe_right,
        is_boolean_right,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        mem_ptr,
        polynomial_size.0 as u32,
        num_blocks,
    );
    cleanup_cuda_integer_mult(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub fn get_mul_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    is_boolean_left: bool,
    is_boolean_right: bool,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    lwe_dimension: LweDimension,
    polynomial_size: PolynomialSize,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_mult_radix_ciphertext_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            is_boolean_left,
            is_boolean_right,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            pbs_type as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_mult(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_bitop_integer_radix_kb_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_left: &mut CudaRadixCiphertext,
    radix_lwe_right: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    op: BitOpType,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_left
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_left_noise_levels = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_lwe_left,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    // Here even though the input is not modified, data is passed as mutable.
    // This avoids having to create two structs for the CudaRadixCiphertext pointers,
    // one const and the other mutable.
    // Having two structs on the Cuda side complicates things as we need to be sure we pass the
    // Const structure as input instead of the mutable structure, which leads to complicated
    // data manipulation on the C++ side to change mutability of data.
    let mut radix_lwe_right_degrees = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_right_noise_levels = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_right = prepare_cuda_radix_ffi(
        radix_lwe_right,
        &mut radix_lwe_right_degrees,
        &mut radix_lwe_right_noise_levels,
    );
    scratch_cuda_integer_radix_bitop_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        op as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_bitop_integer_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_bitop(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub fn get_bitop_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    op: BitOpType,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_bitop_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            op as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_bitop(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_bitop_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_lwe: &mut CudaRadixCiphertext,
    clear_blocks: &CudaVec<T>,
    h_clear_blocks: &[T],
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    op: BitOpType,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        clear_blocks.gpu_index(0),
        "GPU error: first stream is on GPU {}, first clear input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        clear_blocks.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_degrees = radix_lwe.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_noise_levels = radix_lwe
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe = prepare_cuda_radix_ffi(
        radix_lwe,
        &mut radix_lwe_degrees,
        &mut radix_lwe_noise_levels,
    );
    scratch_cuda_integer_radix_bitop_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        op as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe,
        &raw const cuda_ffi_radix_lwe,
        clear_blocks.as_c_ptr(0),
        h_clear_blocks.as_ptr().cast::<std::ffi::c_void>(),
        min(clear_blocks.len() as u32, num_blocks),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_bitop(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe, &cuda_ffi_radix_lwe);
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_bitop_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    op: BitOpType,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_bitop_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            op as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_bitop(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_comparison_integer_radix_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_left: &CudaRadixCiphertext,
    radix_lwe_right: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    op: ComparisonType,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = radix_lwe_left
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_left_degrees = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_left_noise_levels = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_lwe_left,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    let mut radix_lwe_right_degrees = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_right_noise_levels = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_right = prepare_cuda_radix_ffi(
        radix_lwe_right,
        &mut radix_lwe_right_degrees,
        &mut radix_lwe_right_noise_levels,
    );

    scratch_cuda_integer_radix_comparison_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        radix_lwe_left.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        op as u32,
        is_signed,
        true,
        allocate_ms_noise_array,
    );

    cuda_comparison_integer_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );

    cleanup_cuda_integer_comparison(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
pub fn get_comparison_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    op: ComparisonType,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_comparison_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            op as u32,
            is_signed,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_comparison(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_comparison_integer_radix_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_in: &CudaRadixCiphertext,
    scalar_blocks: &CudaVec<T>,
    h_scalar_blocks: &[T],
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_scalar_blocks: u32,
    op: ComparisonType,
    signed_with_positive_scalar: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        scalar_blocks.gpu_index(0),
        "GPU error: first stream is on GPU {}, first scalar input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        scalar_blocks.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_in
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_in_degrees = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_in_noise_levels = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_in = prepare_cuda_radix_ffi(
        radix_lwe_in,
        &mut radix_lwe_in_degrees,
        &mut radix_lwe_in_noise_levels,
    );
    scratch_cuda_integer_radix_comparison_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        op as u32,
        signed_with_positive_scalar,
        true,
        allocate_ms_noise_array,
    );

    cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        scalar_blocks.as_c_ptr(0),
        h_scalar_blocks.as_ptr().cast::<std::ffi::c_void>(),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        num_scalar_blocks,
    );

    cleanup_cuda_integer_comparison(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn full_propagate_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_input: &mut CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_input_degrees = radix_lwe_input
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_input_noise_levels = radix_lwe_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_input = prepare_cuda_radix_ffi(
        radix_lwe_input,
        &mut radix_lwe_input_degrees,
        &mut radix_lwe_input_noise_levels,
    );
    scratch_cuda_full_propagation_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_full_propagation_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
    );
    cleanup_cuda_full_propagation(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_input, &cuda_ffi_radix_lwe_input);
}

#[allow(clippy::too_many_arguments)]
pub fn get_full_propagate_assign_size_on_gpu(
    streams: &CudaStreams,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_full_propagation_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_full_propagation(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub(crate) unsafe fn propagate_single_carry_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_input: &mut CudaRadixCiphertext,
    carry_out: &mut CudaRadixCiphertext,
    carry_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    requested_flag: OutputFlag,
    uses_carry: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = radix_lwe_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let mut radix_lwe_input_degrees = radix_lwe_input
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_input_noise_levels = radix_lwe_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_input = prepare_cuda_radix_ffi(
        radix_lwe_input,
        &mut radix_lwe_input_degrees,
        &mut radix_lwe_input_noise_levels,
    );
    let mut carry_out_degrees = carry_out.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_out_noise_levels = carry_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_carry_out = prepare_cuda_radix_ffi(
        carry_out,
        &mut carry_out_degrees,
        &mut carry_out_noise_levels,
    );
    let mut carry_in_degrees = carry_in.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_in_noise_levels = carry_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_carry_in =
        prepare_cuda_radix_ffi(carry_in, &mut carry_in_degrees, &mut carry_in_noise_levels);
    scratch_cuda_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        requested_flag as u32,
        uses_carry,
        true,
        allocate_ms_noise_array,
    );
    cuda_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        requested_flag as u32,
        uses_carry,
    );
    cleanup_cuda_propagate_single_carry(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_input, &cuda_ffi_radix_lwe_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn get_propagate_single_carry_assign_async_size_on_gpu(
    streams: &CudaStreams,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    requested_flag: OutputFlag,
    uses_carry: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let size_tracker = unsafe {
        scratch_cuda_propagate_single_carry_kb_64_inplace(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            requested_flag as u32,
            uses_carry,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_propagate_single_carry(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn get_add_and_propagate_single_carry_assign_async_size_on_gpu(
    streams: &CudaStreams,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    requested_flag: OutputFlag,
    uses_carry: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let size_tracker = unsafe {
        scratch_cuda_add_and_propagate_single_carry_kb_64_inplace(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            requested_flag as u32,
            uses_carry,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_add_and_propagate_single_carry(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub(crate) unsafe fn sub_and_propagate_single_carry_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lhs_input: &mut CudaRadixCiphertext,
    rhs_input: &CudaRadixCiphertext,
    carry_out: &mut CudaRadixCiphertext,
    carry_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    requested_flag: OutputFlag,
    uses_carry: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lhs_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        carry_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first carry_out pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        carry_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        carry_in.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first carry_in pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        carry_in.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = lhs_input.d_blocks.ciphertext_modulus().raw_modulus_float();

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);

    let allocate_ms_noise_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;

    let mut lhs_input_degrees = lhs_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut lhs_input_noise_levels = lhs_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_lhs_input = prepare_cuda_radix_ffi(
        lhs_input,
        &mut lhs_input_degrees,
        &mut lhs_input_noise_levels,
    );

    let mut rhs_input_degrees = rhs_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut rhs_input_noise_levels = rhs_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_rhs_input = prepare_cuda_radix_ffi(
        rhs_input,
        &mut rhs_input_degrees,
        &mut rhs_input_noise_levels,
    );

    let mut carry_out_degrees = carry_out.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_out_noise_levels = carry_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_carry_out = prepare_cuda_radix_ffi(
        carry_out,
        &mut carry_out_degrees,
        &mut carry_out_noise_levels,
    );

    let mut carry_in_degrees = carry_in.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_in_noise_levels = carry_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_carry_in =
        prepare_cuda_radix_ffi(carry_in, &mut carry_in_degrees, &mut carry_in_noise_levels);

    scratch_cuda_sub_and_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        requested_flag as u32,
        true,
        allocate_ms_noise_array,
    );

    cuda_sub_and_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_lhs_input,
        &raw const cuda_ffi_rhs_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        requested_flag as u32,
        uses_carry,
    );

    cleanup_cuda_sub_and_propagate_single_carry(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(lhs_input, &cuda_ffi_lhs_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub(crate) unsafe fn add_and_propagate_single_carry_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lhs_input: &mut CudaRadixCiphertext,
    rhs_input: &CudaRadixCiphertext,
    carry_out: &mut CudaRadixCiphertext,
    carry_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    requested_flag: OutputFlag,
    uses_carry: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lhs_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        carry_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first carry_out pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        carry_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        carry_in.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first carry_in pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        carry_in.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = lhs_input.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let mut lhs_input_degrees = lhs_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut lhs_input_noise_levels = lhs_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_lhs_input = prepare_cuda_radix_ffi(
        lhs_input,
        &mut lhs_input_degrees,
        &mut lhs_input_noise_levels,
    );
    let mut rhs_input_degrees = rhs_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut rhs_input_noise_levels = rhs_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_rhs_input = prepare_cuda_radix_ffi(
        rhs_input,
        &mut rhs_input_degrees,
        &mut rhs_input_noise_levels,
    );
    let mut carry_out_degrees = carry_out.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_out_noise_levels = carry_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_carry_out = prepare_cuda_radix_ffi(
        carry_out,
        &mut carry_out_degrees,
        &mut carry_out_noise_levels,
    );
    let mut carry_in_degrees = carry_in.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_in_noise_levels = carry_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_carry_in =
        prepare_cuda_radix_ffi(carry_in, &mut carry_in_degrees, &mut carry_in_noise_levels);
    scratch_cuda_add_and_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        requested_flag as u32,
        uses_carry,
        true,
        allocate_ms_noise_array,
    );
    cuda_add_and_propagate_single_carry_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_lhs_input,
        &raw const cuda_ffi_rhs_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        requested_flag as u32,
        uses_carry,
    );
    cleanup_cuda_add_and_propagate_single_carry(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(lhs_input, &cuda_ffi_lhs_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_unsigned_scalar_div_rem_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    quotient: &mut CudaRadixCiphertext,
    remainder: &mut CudaRadixCiphertext,
    rhs: Scalar,
    divisor: Scalar,
    msg_bits: usize,
    ksks: &CudaVec<T>,
    bsks: &CudaVec<B>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    multiplier_exceeds_threshold: bool,
    is_divisor_power_of_two: bool,
    log2_divisor_exceeds_threshold: bool,
    ilog2_divisor: u32,
    shift_pre: u64,
    shift_post: u32,
    h_clear_blocks: &[T],
    clear_blocks: &CudaVec<T>,
    pbs_type: PBSType,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    assert_eq!(
        streams.gpu_indexes[0],
        quotient.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(streams.gpu_indexes[0], ksks.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bsks.gpu_index(0));

    let ct_modulus = quotient.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut quotient_degrees = quotient.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut quotient_noise_levels = quotient
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();

    let mut cuda_ffi_quotient =
        prepare_cuda_radix_ffi(quotient, &mut quotient_degrees, &mut quotient_noise_levels);
    let mut cuda_ffi_remainder =
        prepare_cuda_radix_ffi(remainder, &mut quotient_degrees, &mut quotient_noise_levels);

    let decomposed_scalar_for_div = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer_for_div = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

    let mut has_at_least_one_set_for_div = vec![0u64; msg_bits];
    for (i, bit) in decomposer_for_div.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set_for_div[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits_for_div = 2 * msg_bits * num_blocks as usize;
    let num_scalar_bits_for_div = decomposed_scalar_for_div
        .iter()
        .take(num_ciphertext_bits_for_div)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let decomposed_scalar_for_mul = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer_for_mul = BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();

    let mut has_at_least_one_set_for_mul = vec![0u64; msg_bits];
    for (i, bit) in decomposer_for_mul.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set_for_mul[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits_for_mul = msg_bits * num_blocks as usize;
    let num_scalar_bits_for_mul = decomposed_scalar_for_mul
        .iter()
        .take(num_ciphertext_bits_for_mul)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    scratch_integer_unsigned_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        is_divisor_power_of_two,
        log2_divisor_exceeds_threshold,
        multiplier_exceeds_threshold,
        num_scalar_bits_for_div,
        num_scalar_bits_for_mul,
        ilog2_divisor,
        divisor.cast_into(),
        allocate_ms_array,
    );

    cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        mem_ptr,
        ksks.ptr.as_ptr(),
        bsks.ptr.as_ptr(),
        decomposed_scalar_for_div.as_ptr(),
        decomposed_scalar_for_mul.as_ptr(),
        has_at_least_one_set_for_div.as_ptr(),
        has_at_least_one_set_for_mul.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        decomposed_scalar_for_div.len() as u32,
        decomposed_scalar_for_mul.len() as u32,
        multiplier_exceeds_threshold,
        is_divisor_power_of_two,
        log2_divisor_exceeds_threshold,
        ilog2_divisor,
        divisor.cast_into(),
        shift_pre,
        shift_post,
        rhs.cast_into(),
        clear_blocks.as_c_ptr(0),
        h_clear_blocks.as_ptr().cast::<std::ffi::c_void>(),
        min(clear_blocks.len() as u32, num_blocks),
    );

    cleanup_cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_signed_scalar_div_rem_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    quotient: &mut CudaRadixCiphertext,
    remainder: &mut CudaRadixCiphertext,
    ksks: &CudaVec<T>,
    bsks: &CudaVec<B>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    shift_post: u32,
    pbs_type: PBSType,
    is_absolute_divisor_one: bool,
    is_divisor_negative: bool,
    l_exceed_threshold: bool,
    is_absolute_divisor_power_of_two: bool,
    is_divisor_zero: bool,
    multiplier_is_small: bool,
    l: u32,
    is_rhs_power_of_two: bool,
    is_rhs_zero: bool,
    is_rhs_one: bool,
    rhs_shift: u32,
    divisor_shift: u32,
    numerator_bits: u32,
    num_scalar_bits_for_div: u32,
    num_scalar_bits_for_mul: u32,
    num_scalars_for_div: u32,
    num_scalars_for_mul: u32,
    decomposed_scalar_for_div: *const u64,
    decomposed_scalar_for_mul: *const u64,
    has_at_least_one_set_for_div: *const u64,
    has_at_least_one_set_for_mul: *const u64,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        quotient.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(streams.gpu_indexes[0], ksks.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bsks.gpu_index(0));

    let ct_modulus = quotient.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut quotient_degrees = quotient.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut quotient_noise_levels = quotient
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();

    let mut cuda_ffi_quotient =
        prepare_cuda_radix_ffi(quotient, &mut quotient_degrees, &mut quotient_noise_levels);
    let mut cuda_ffi_remainder =
        prepare_cuda_radix_ffi(remainder, &mut quotient_degrees, &mut quotient_noise_levels);

    scratch_integer_signed_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        num_scalar_bits_for_div,
        num_scalar_bits_for_mul,
        is_absolute_divisor_one,
        is_divisor_negative,
        l_exceed_threshold,
        is_absolute_divisor_power_of_two,
        is_divisor_zero,
        multiplier_is_small,
        allocate_ms_array,
    );

    cuda_integer_signed_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        mem_ptr,
        ksks.ptr.as_ptr(),
        bsks.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        is_absolute_divisor_one,
        is_divisor_negative,
        is_divisor_zero,
        l_exceed_threshold,
        is_absolute_divisor_power_of_two,
        multiplier_is_small,
        l,
        shift_post,
        is_rhs_power_of_two,
        is_rhs_zero,
        is_rhs_one,
        rhs_shift,
        divisor_shift,
        numerator_bits,
        num_scalars_for_div,
        num_scalars_for_mul,
        decomposed_scalar_for_div,
        decomposed_scalar_for_mul,
        has_at_least_one_set_for_div,
        has_at_least_one_set_for_mul,
    );

    cleanup_cuda_integer_signed_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn get_scalar_div_rem_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    rhs: Scalar,
    divisor: Scalar,
    msg_bits: usize,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    multiplier_exceeds_threshold: bool,
    is_divisor_power_of_two: bool,
    log2_divisor_exceeds_threshold: bool,
    ilog2_divisor: u32,
    pbs_type: PBSType,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64
where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let allocate_ms_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let decomposed_scalar_for_div = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer_for_div = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

    let mut has_at_least_one_set_for_div = vec![0u64; msg_bits];
    for (i, bit) in decomposer_for_div.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set_for_div[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits_for_div = 2 * msg_bits * num_blocks as usize;
    let num_scalar_bits_for_div = decomposed_scalar_for_div
        .iter()
        .take(num_ciphertext_bits_for_div)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let decomposed_scalar_for_mul = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer_for_mul = BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();

    let mut has_at_least_one_set_for_mul = vec![0u64; msg_bits];
    for (i, bit) in decomposer_for_mul.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set_for_mul[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits_for_mul = msg_bits * num_blocks as usize;
    let num_scalar_bits_for_mul = decomposed_scalar_for_mul
        .iter()
        .take(num_ciphertext_bits_for_mul)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let size_tracker = scratch_integer_unsigned_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        false,
        is_divisor_power_of_two,
        log2_divisor_exceeds_threshold,
        multiplier_exceeds_threshold,
        num_scalar_bits_for_div,
        num_scalar_bits_for_mul,
        ilog2_divisor,
        divisor.cast_into(),
        allocate_ms_array,
    );

    cleanup_cuda_integer_unsigned_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    size_tracker
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn get_signed_scalar_div_rem_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    pbs_type: PBSType,
    is_absolute_divisor_one: bool,
    is_divisor_negative: bool,
    l_exceed_threshold: bool,
    is_absolute_divisor_power_of_two: bool,
    is_divisor_zero: bool,
    multiplier_is_small: bool,
    num_scalar_bits_for_div: u32,
    num_scalar_bits_for_mul: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = scratch_integer_signed_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        false,
        num_scalar_bits_for_div,
        num_scalar_bits_for_mul,
        is_absolute_divisor_one,
        is_divisor_negative,
        l_exceed_threshold,
        is_absolute_divisor_power_of_two,
        is_divisor_zero,
        multiplier_is_small,
        allocate_ms_array,
    );

    cleanup_cuda_integer_signed_scalar_div_rem_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_unsigned_scalar_div_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    numerator: &mut CudaRadixCiphertext,
    rhs: Scalar,
    msg_bits: usize,
    ksks: &CudaVec<T>,
    bsks: &CudaVec<B>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    multiplier_exceeds_threshold: bool,
    is_divisor_power_of_two: bool,
    log2_divisor_exceeds_threshold: bool,
    ilog2_divisor: u32,
    shift_pre: u64,
    shift_post: u32,
    pbs_type: PBSType,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    assert_eq!(
        streams.gpu_indexes[0],
        numerator.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(streams.gpu_indexes[0], ksks.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bsks.gpu_index(0));

    let ct_modulus = numerator.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut numerator_degrees = numerator.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut numerator_noise_levels = numerator
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_numerator = prepare_cuda_radix_ffi(
        numerator,
        &mut numerator_degrees,
        &mut numerator_noise_levels,
    );

    let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

    let mut has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    scratch_cuda_integer_unsigned_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        is_divisor_power_of_two,
        log2_divisor_exceeds_threshold,
        multiplier_exceeds_threshold,
        num_scalar_bits,
        ilog2_divisor,
        allocate_ms_array,
    );

    cuda_integer_unsigned_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_numerator,
        mem_ptr,
        ksks.ptr.as_ptr(),
        decomposed_scalar.as_ptr(),
        has_at_least_one_set.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bsks.ptr.as_ptr(),
        decomposed_scalar.len() as u32,
        multiplier_exceeds_threshold,
        is_divisor_power_of_two,
        log2_divisor_exceeds_threshold,
        ilog2_divisor,
        shift_pre,
        shift_post,
        rhs.cast_into(),
    );

    cleanup_cuda_integer_unsigned_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(numerator, &cuda_ffi_numerator);
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_signed_scalar_div_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    numerator: &mut CudaRadixCiphertext,
    ksks: &CudaVec<T>,
    bsks: &CudaVec<B>,
    rhs: Scalar,
    msg_bits: usize,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    num_blocks: u32,
    pbs_type: PBSType,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    is_absolute_divisor_one: bool,
    is_divisor_negative: bool,
    l_exceed_threshold: bool,
    is_power_of_two: bool,
    multiplier_is_small: bool,
    l: u32,
    shift_post: u32,
    numerator_bits: u32,
) where
    Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    assert_eq!(
        streams.gpu_indexes[0],
        numerator.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(streams.gpu_indexes[0], ksks.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bsks.gpu_index(0));

    let ct_modulus = numerator.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut numerator_degrees = numerator.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut numerator_noise_levels = numerator
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_numerator = prepare_cuda_radix_ffi(
        numerator,
        &mut numerator_degrees,
        &mut numerator_noise_levels,
    );

    let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

    let mut has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            has_at_least_one_set[i % msg_bits] = 1;
        }
    }

    let num_ciphertext_bits = msg_bits * 2 * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .as_slice()
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let is_rhs_power_of_two = rhs.is_power_of_two();
    let is_rhs_zero = rhs == Scalar::ZERO;
    let is_rhs_one = rhs == Scalar::ONE;
    let rhs_shift = if is_rhs_power_of_two && !is_rhs_one {
        rhs.ilog2()
    } else {
        0u32
    };

    scratch_cuda_integer_signed_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        num_scalar_bits,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        is_absolute_divisor_one,
        is_divisor_negative,
        l_exceed_threshold,
        is_power_of_two,
        multiplier_is_small,
        allocate_ms_array,
    );

    cuda_integer_signed_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_numerator,
        mem_ptr,
        ksks.ptr.as_ptr(),
        bsks.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        is_absolute_divisor_one,
        is_divisor_negative,
        l_exceed_threshold,
        is_power_of_two,
        multiplier_is_small,
        l,
        shift_post,
        is_rhs_power_of_two,
        is_rhs_zero,
        is_rhs_one,
        rhs_shift,
        numerator_bits,
        decomposed_scalar.len() as u32,
        decomposed_scalar.as_slice().as_ptr().cast::<u64>(),
        has_at_least_one_set.as_slice().as_ptr().cast::<u64>(),
    );

    cleanup_cuda_integer_signed_scalar_div_radix_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(numerator, &cuda_ffi_numerator);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_left_shift_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    input: &mut CudaRadixCiphertext,
    shift: u32,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = input.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::LeftShift as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_logical_scalar_shift(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    input: &mut CudaRadixCiphertext,
    shift: u32,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = input.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::RightShift as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_logical_scalar_shift(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_arithmetic_right_shift_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    input: &mut CudaRadixCiphertext,
    shift: u32,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = input.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        input.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::RightShift as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_arithmetic_scalar_shift(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_right_shift_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    radix_shift: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_shift.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first shift pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_shift.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    let mut radix_shift_degrees = radix_shift.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_shift_noise_levels = radix_shift
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_shift = prepare_cuda_radix_ffi(
        radix_shift,
        &mut radix_shift_degrees,
        &mut radix_shift_noise_levels,
    );

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::RightShift as u32,
        is_signed,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_shift_and_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_shift_and_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_left_shift_integer_radix_kb_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    radix_shift: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_shift.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first shift pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_shift.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    let mut radix_shift_degrees = radix_shift.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_shift_noise_levels = radix_shift
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_shift = prepare_cuda_radix_ffi(
        radix_shift,
        &mut radix_shift_degrees,
        &mut radix_shift_noise_levels,
    );

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::LeftShift as u32,
        is_signed,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_shift_and_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_shift_and_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_rotate_right_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    radix_rotation: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_rotation.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rotation pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_rotation.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    let mut radix_shift_degrees = radix_rotation
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_shift_noise_levels = radix_rotation
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_shift = prepare_cuda_radix_ffi(
        radix_rotation,
        &mut radix_shift_degrees,
        &mut radix_shift_noise_levels,
    );

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::RightRotate as u32,
        is_signed,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_shift_and_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_shift_and_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_rotate_left_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    radix_rotation: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_rotation.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rotation pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_rotation.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    let mut radix_shift_degrees = radix_rotation
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_shift_noise_levels = radix_rotation
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_shift = prepare_cuda_radix_ffi(
        radix_rotation,
        &mut radix_shift_degrees,
        &mut radix_shift_noise_levels,
    );

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_radix_shift_and_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::LeftRotate as u32,
        is_signed,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_shift_and_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_shift_and_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_left_shift_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::LeftShift as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_logical_scalar_shift(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_logical_right_shift_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::RightShift as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_logical_scalar_shift(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_arithmetic_right_shift_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::RightShift as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_arithmetic_scalar_shift(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_right_shift_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::RightShift as u32,
            is_signed,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_shift_and_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_left_shift_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::LeftShift as u32,
            is_signed,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_shift_and_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_rotate_right_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::RightRotate as u32,
            is_signed,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_shift_and_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_rotate_left_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    is_signed: bool,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::LeftRotate as u32,
            is_signed,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_shift_and_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_cmux_integer_radix_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_condition: &CudaBooleanBlock,
    radix_lwe_true: &CudaRadixCiphertext,
    radix_lwe_false: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_condition
            .0
            .ciphertext
            .d_blocks
            .0
            .d_vec
            .gpu_index(0),
        "GPU error: first stream is on GPU {}, first condition pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_condition
            .0
            .ciphertext
            .d_blocks
            .0
            .d_vec
            .gpu_index(0)
            .get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_true.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first true pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_true.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_false.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first false pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_false.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_out
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();

    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_true_degrees = radix_lwe_true
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_true_noise_levels = radix_lwe_true
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_true = prepare_cuda_radix_ffi(
        radix_lwe_true,
        &mut radix_lwe_true_degrees,
        &mut radix_lwe_true_noise_levels,
    );
    let mut radix_lwe_false_degrees = radix_lwe_false
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_false_noise_levels = radix_lwe_false
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_false = prepare_cuda_radix_ffi(
        radix_lwe_false,
        &mut radix_lwe_false_degrees,
        &mut radix_lwe_false_noise_levels,
    );
    let mut condition_degrees = radix_lwe_condition
        .0
        .ciphertext
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut condition_noise_levels = radix_lwe_condition
        .0
        .ciphertext
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_condition = prepare_cuda_radix_ffi(
        &radix_lwe_condition.0.ciphertext,
        &mut condition_degrees,
        &mut condition_noise_levels,
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_radix_cmux_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_cmux_integer_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_condition,
        &raw const cuda_ffi_radix_lwe_true,
        &raw const cuda_ffi_radix_lwe_false,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_cmux(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
pub fn get_cmux_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_cmux_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_cmux(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_rotate_left_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    n: u32,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    scratch_cuda_integer_radix_scalar_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::LeftShift as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_scalar_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        n,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_scalar_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_scalar_rotate_right_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_input: &mut CudaRadixCiphertext,
    n: u32,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_input.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_input.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_input
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = radix_input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels = radix_input
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    scratch_cuda_integer_radix_scalar_rotate_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        ShiftRotateType::RightShift as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_scalar_rotate_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        n,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_scalar_rotate(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_rotate_left_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::LeftShift as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_scalar_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub fn get_scalar_rotate_right_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            ShiftRotateType::RightShift as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_radix_scalar_rotate(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_partial_sum_ciphertexts_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    result: &mut CudaRadixCiphertext,
    radix_list: &mut CudaRadixCiphertext,
    reduce_degrees_for_single_carry_propagation: bool,
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
    num_blocks: u32,
    num_radixes: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        result.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        result.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_list.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_list.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_list.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut result_degrees = result.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut result_noise_levels = result.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_result =
        prepare_cuda_radix_ffi(result, &mut result_degrees, &mut result_noise_levels);
    let mut radix_list_degrees = radix_list.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_list_noise_levels = radix_list
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_list = prepare_cuda_radix_ffi(
        radix_list,
        &mut radix_list_degrees,
        &mut radix_list_noise_levels,
    );
    scratch_cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        num_radixes,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        reduce_degrees_for_single_carry_propagation,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_result,
        &raw mut cuda_ffi_radix_list,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_radix_partial_sum_ciphertexts_vec(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(result, &cuda_ffi_result);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn extend_radix_with_sign_msb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaRadixCiphertext,
    ct: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_additional_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    let message_modulus = ct.info.blocks.first().unwrap().message_modulus;
    let carry_modulus = ct.info.blocks.first().unwrap().carry_modulus;
    let ct_modulus = ct.d_blocks.ciphertext_modulus().raw_modulus_float();

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut input_degrees = ct.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut input_noise_levels = ct.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_radix_input =
        prepare_cuda_radix_ffi(ct, &mut input_degrees, &mut input_noise_levels);

    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    scratch_cuda_extend_radix_with_sign_msb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        1u32,
        num_additional_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );

    cuda_extend_radix_with_sign_msb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_output,
        &raw const cuda_ffi_radix_input,
        mem_ptr,
        num_additional_blocks,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );

    cleanup_cuda_extend_radix_with_sign_msb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(output, &cuda_ffi_radix_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn apply_univariate_lut_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    input: &CudaSlice<T>,
    input_lut: &[T],
    lut_degree: u64,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    ct_modulus: f64,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut cuda_ffi_output = prepare_cuda_radix_ffi_from_slice_mut(
        output,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let cuda_ffi_input = prepare_cuda_radix_ffi_from_slice(
        input,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    scratch_cuda_apply_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        input_lut.as_ptr().cast(),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        lut_degree,
        true,
        allocate_ms_noise_array,
    );
    cuda_apply_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
    );
    cleanup_cuda_apply_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn apply_many_univariate_lut_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    input: &CudaSlice<T>,
    input_lut: &[T],
    lut_degree: u64,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    num_many_lut: u32,
    lut_stride: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    ct_modulus: f64,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut cuda_ffi_output = prepare_cuda_radix_ffi_from_slice_mut(
        output,
        output_degrees,
        output_noise_levels,
        num_blocks * num_many_lut,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let cuda_ffi_input = prepare_cuda_radix_ffi_from_slice(
        input,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    scratch_cuda_apply_many_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        input_lut.as_ptr().cast(),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        num_many_lut,
        lut_degree,
        true,
        allocate_ms_noise_array,
    );
    cuda_apply_many_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
        num_many_lut,
        lut_stride,
    );
    cleanup_cuda_apply_univariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn apply_bivariate_lut_kb_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    input_1: &CudaSlice<T>,
    input_2: &CudaSlice<T>,
    input_lut: &[T],
    lut_degree: u64,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    shift: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    ct_modulus: f64,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input_1.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input 1 pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_1.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_2.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input 2 pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_2.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut cuda_ffi_output = prepare_cuda_radix_ffi_from_slice_mut(
        output,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let cuda_ffi_input_1 = prepare_cuda_radix_ffi_from_slice(
        input_1,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let cuda_ffi_input_2 = prepare_cuda_radix_ffi_from_slice(
        input_2,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    scratch_cuda_apply_bivariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        input_lut.as_ptr().cast(),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        lut_degree,
        true,
        allocate_ms_noise_array,
    );
    cuda_apply_bivariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input_1,
        &raw const cuda_ffi_input_2,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
        shift,
    );
    cleanup_cuda_apply_bivariate_lut_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_div_rem_integer_radix_kb_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    quotient: &mut CudaRadixCiphertext,
    remainder: &mut CudaRadixCiphertext,
    numerator: &CudaRadixCiphertext,
    divisor: &CudaRadixCiphertext,
    is_signed: bool,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        quotient.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first quotient pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        quotient.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        remainder.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first remainder pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        remainder.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        numerator.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first numerator pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        numerator.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        divisor.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first divisor pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        divisor.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = numerator.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut quotient_degrees = quotient.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut quotient_noise_levels = quotient
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_quotient =
        prepare_cuda_radix_ffi(quotient, &mut quotient_degrees, &mut quotient_noise_levels);
    let mut divisor_degrees = divisor.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut divisor_noise_levels = divisor
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_divisor =
        prepare_cuda_radix_ffi(divisor, &mut divisor_degrees, &mut divisor_noise_levels);
    let mut numerator_degrees = numerator.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut numerator_noise_levels = numerator
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_numerator = prepare_cuda_radix_ffi(
        numerator,
        &mut numerator_degrees,
        &mut numerator_noise_levels,
    );
    let mut remainder_degrees = remainder.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut remainder_noise_levels = remainder
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_remainder = prepare_cuda_radix_ffi(
        remainder,
        &mut remainder_degrees,
        &mut remainder_noise_levels,
    );
    scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        is_signed,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_div_rem_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        &raw const cuda_ffi_numerator,
        &raw const cuda_ffi_divisor,
        is_signed,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_div_rem(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
pub fn get_div_rem_integer_radix_kb_size_on_gpu(
    streams: &CudaStreams,
    is_signed: bool,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) -> u64 {
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            is_signed,
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            allocate_ms_noise_array,
        )
    };
    unsafe {
        cleanup_cuda_integer_div_rem(
            streams.ptr.as_ptr(),
            streams.gpu_indexes_ptr(),
            streams.len() as u32,
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn compute_prefix_sum_hillis_steele_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    generates_or_propagates: &mut CudaSliceMut<T>,
    generates_or_propagates_degrees: &mut Vec<u64>,
    generates_or_propagates_noise_levels: &mut Vec<u64>,
    input_lut: &[T],
    lut_degree: u64,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    ct_modulus: f64,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        generates_or_propagates.gpu_index(0),
        "GPU error: first stream is on GPU {}, first generates_or_propagates pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        generates_or_propagates.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut cuda_ffi_output = prepare_cuda_radix_ffi_from_slice_mut(
        output,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let mut cuda_ffi_generates_or_propagates = prepare_cuda_radix_ffi_from_slice_mut(
        generates_or_propagates,
        generates_or_propagates_degrees,
        generates_or_propagates_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    scratch_cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        input_lut.as_ptr().cast(),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        lut_degree,
        true,
        allocate_ms_noise_array,
    );

    cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_output,
        &raw mut cuda_ffi_generates_or_propagates,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
    );

    cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn reverse_blocks_inplace_async(
    streams: &CudaStreams,
    radix_lwe_output: &mut CudaRadixCiphertext,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_output.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_output.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    if radix_lwe_output.d_blocks.lwe_ciphertext_count().0 > 1 {
        let mut radix_lwe_output_degrees = radix_lwe_output
            .info
            .blocks
            .iter()
            .map(|b| b.degree.0)
            .collect();
        let mut radix_lwe_output_noise_levels = radix_lwe_output
            .info
            .blocks
            .iter()
            .map(|b| b.noise_level.0)
            .collect();
        let mut cuda_ffi_radix_lwe_output = prepare_cuda_radix_ffi(
            radix_lwe_output,
            &mut radix_lwe_output_degrees,
            &mut radix_lwe_output_noise_levels,
        );
        cuda_integer_reverse_blocks_64_inplace(
            streams.ptr.as_ptr(),
            streams
                .gpu_indexes
                .iter()
                .map(|i| i.get())
                .collect::<Vec<u32>>()
                .as_ptr(),
            streams.len() as u32,
            &raw mut cuda_ffi_radix_lwe_output,
        );
        update_noise_degree(radix_lwe_output, &cuda_ffi_radix_lwe_output);
    }
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub(crate) unsafe fn unchecked_unsigned_overflowing_sub_integer_radix_kb_assign_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_lwe_left: &mut CudaRadixCiphertext,
    radix_lwe_right: &CudaRadixCiphertext,
    carry_out: &mut CudaRadixCiphertext,
    carry_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    compute_overflow: bool,
    uses_input_borrow: u32,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_left.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_right.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_left
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let mut radix_lwe_left_degrees = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_left_noise_levels = radix_lwe_left
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        radix_lwe_left,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );
    let mut radix_lwe_right_degrees = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_right_noise_levels = radix_lwe_right
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_right = prepare_cuda_radix_ffi(
        radix_lwe_right,
        &mut radix_lwe_right_degrees,
        &mut radix_lwe_right_noise_levels,
    );
    let mut carry_out_degrees = carry_out.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_out_noise_levels = carry_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_carry_out = prepare_cuda_radix_ffi(
        carry_out,
        &mut carry_out_degrees,
        &mut carry_out_noise_levels,
    );
    let mut carry_in_degrees = carry_in.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut carry_in_noise_levels = carry_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_carry_in =
        prepare_cuda_radix_ffi(carry_in, &mut carry_in_degrees, &mut carry_in_noise_levels);
    scratch_cuda_integer_overflowing_sub_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        radix_lwe_left.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        compute_overflow as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_overflowing_sub_kb_64_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        compute_overflow as u32,
        uses_input_borrow,
    );
    cleanup_cuda_integer_overflowing_sub(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_signed_abs_radix_kb_assign_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    ct: &mut CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        ct.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        ct.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );

    let ct_modulus = ct.d_blocks.ciphertext_modulus().raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut ct_degrees = ct.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut ct_noise_levels = ct.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_ct = prepare_cuda_radix_ffi(ct, &mut ct_degrees, &mut ct_noise_levels);
    scratch_cuda_integer_abs_inplace_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        true,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_integer_abs_inplace_radix_ciphertext_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_ct,
        mem_ptr,
        true,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_cuda_integer_abs_inplace(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(ct, &cuda_ffi_ct);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_is_at_least_one_comparisons_block_true_integer_radix_kb_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_in
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_in_degrees = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_in_noise_levels = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_in = prepare_cuda_radix_ffi(
        radix_lwe_in,
        &mut radix_lwe_in_degrees,
        &mut radix_lwe_in_noise_levels,
    );
    scratch_cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );

    cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
    );

    cleanup_cuda_integer_is_at_least_one_comparisons_block_true(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn unchecked_are_all_comparisons_block_true_integer_radix_kb_async<
    T: UnsignedInteger,
    B: Numeric,
>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_in: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        radix_lwe_in.d_blocks.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ct_modulus = radix_lwe_in
        .d_blocks
        .ciphertext_modulus()
        .raw_modulus_float();
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_in_degrees = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_in_noise_levels = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_in = prepare_cuda_radix_ffi(
        radix_lwe_in,
        &mut radix_lwe_in_degrees,
        &mut radix_lwe_in_noise_levels,
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_are_all_comparisons_block_true_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );

    cuda_integer_are_all_comparisons_block_true_kb_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
    );

    cleanup_cuda_integer_are_all_comparisons_block_true(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// Assign negation of a vector of LWE ciphertexts representing an integer
///
/// # Safety
///
/// [CudaStreams::synchronize] __must__ be called as soon as synchronization is
/// required
pub unsafe fn unchecked_negate_integer_radix_async(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    radix_lwe_in: &CudaRadixCiphertext,
    message_modulus: u32,
    carry_modulus: u32,
) {
    let mut radix_lwe_out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out = prepare_cuda_radix_ffi(
        radix_lwe_out,
        &mut radix_lwe_out_degrees,
        &mut radix_lwe_out_noise_levels,
    );
    let mut radix_lwe_in_degrees = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut radix_lwe_in_noise_levels = radix_lwe_in
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_radix_lwe_in = prepare_cuda_radix_ffi(
        radix_lwe_in,
        &mut radix_lwe_in_degrees,
        &mut radix_lwe_in_noise_levels,
    );

    cuda_negate_integer_radix_ciphertext_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        message_modulus,
        carry_modulus,
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

/// # Safety
///
/// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until streams is synchronized
pub unsafe fn trim_radix_blocks_lsb_async(
    output: &mut CudaRadixCiphertext,
    input: &CudaRadixCiphertext,
    streams: &CudaStreams,
) {
    let mut input_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut input_noise_levels = input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();

    let mut cuda_ffi_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    let cuda_ffi_input = prepare_cuda_radix_ffi(input, &mut input_degrees, &mut input_noise_levels);

    trim_radix_blocks_lsb_64(
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
    );
    update_noise_degree(output, &cuda_ffi_output);
}

/// # Safety
///
/// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until streams is synchronized
pub unsafe fn extend_radix_with_trivial_zero_blocks_msb_async(
    output: &mut CudaRadixCiphertext,
    input: &CudaRadixCiphertext,
    streams: &CudaStreams,
) {
    let mut input_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut input_noise_levels = input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();

    let mut cuda_ffi_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    let cuda_ffi_input = prepare_cuda_radix_ffi(input, &mut input_degrees, &mut input_noise_levels);

    extend_radix_with_trivial_zero_blocks_msb_64(
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
    );

    update_noise_degree(output, &cuda_ffi_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - [CudaStreams::synchronize] __must__ be called after this function as soon as synchronization
///   is required
pub unsafe fn noise_squashing_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    input: &CudaSlice<u64>,
    bootstrapping_key: &CudaVec<f64>,
    keyswitch_key: &CudaVec<u64>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    input_glwe_dimension: GlweDimension,
    input_polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    num_blocks: u32,
    original_num_blocks: u32,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    grouping_factor: LweBskGroupingFactor,
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
    ct_modulus: f64,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        input.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.gpu_index(0).get(),
    );
    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);

    let allocate_ms_noise_array = noise_reduction_key.is_some();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut cuda_ffi_output = prepare_cuda_radix_ffi_from_slice_mut(
        output,
        output_degrees,
        output_noise_levels,
        num_blocks,
        (glwe_dimension.0 * polynomial_size.0) as u32,
    );
    let cuda_ffi_input = prepare_cuda_radix_ffi_from_slice(
        input,
        output_degrees,
        output_noise_levels,
        original_num_blocks,
        (input_glwe_dimension.0 * input_polynomial_size.0) as u32,
    );

    scratch_cuda_apply_noise_squashing_kb(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        lwe_dimension.0 as u32,
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        input_glwe_dimension.0 as u32,
        input_polynomial_size.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks,
        original_num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        allocate_ms_noise_array,
    );

    cuda_apply_noise_squashing_kb(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
        bootstrapping_key.ptr.as_ptr(),
    );

    cleanup_cuda_apply_noise_squashing_kb(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
///
///
/// In this method, the input `lwe_flattened_compact_array_in` represents a flattened compact list.
/// Instead of receiving a `Vec<CompactCiphertextList>`, it takes a concatenation of all LWEs
/// that were inside that vector of compact list. Handling the input this way removes the need
/// to process multiple compact lists separately, simplifying GPU-based operations. The variable
/// name `lwe_flattened_compact_array_in` makes this intent explicit.
pub unsafe fn expand_async<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaLweCiphertextList<T>,
    lwe_flattened_compact_array_in: &CudaVec<T>,
    bootstrapping_key: &CudaVec<B>,
    computing_ks_key: &CudaVec<T>,
    casting_key: &CudaVec<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    computing_glwe_dimension: GlweDimension,
    computing_polynomial_size: PolynomialSize,
    computing_lwe_dimension: LweDimension,
    computing_ks_level: DecompositionLevelCount,
    computing_ks_base_log: DecompositionBaseLog,
    casting_input_lwe_dimension: LweDimension,
    casting_output_lwe_dimension: LweDimension,
    casting_ks_level: DecompositionLevelCount,
    casting_ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    pbs_type: PBSType,
    casting_key_type: KsType,
    grouping_factor: LweBskGroupingFactor,
    num_lwes_per_compact_list: &[u32],
    is_boolean: &[bool],
    noise_reduction_key: Option<&CudaModulusSwitchNoiseReductionKey>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array_out.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array_out.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_flattened_compact_array_in.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_flattened_compact_array_in.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_indexes[0],
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bootstrapping_key.gpu_indexes[0].get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        computing_ks_key.gpu_indexes[0],
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        computing_ks_key.gpu_indexes[0].get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        casting_key.gpu_indexes[0],
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        casting_key.gpu_indexes[0].get(),
    );
    let ct_modulus = lwe_array_out.ciphertext_modulus().raw_modulus_float();
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let num_compact_lists = num_lwes_per_compact_list.len();

    let ms_noise_reduction_key_ffi =
        prepare_cuda_ms_noise_reduction_key_ffi(noise_reduction_key, ct_modulus);
    let allocate_ms_noise_array = noise_reduction_key.is_some();

    scratch_cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
        computing_glwe_dimension.0 as u32,
        computing_polynomial_size.0 as u32,
        computing_glwe_dimension
            .to_equivalent_lwe_dimension(computing_polynomial_size)
            .0 as u32,
        computing_lwe_dimension.0 as u32,
        computing_ks_level.0 as u32,
        computing_ks_base_log.0 as u32,
        casting_input_lwe_dimension.0 as u32,
        casting_output_lwe_dimension.0 as u32,
        casting_ks_level.0 as u32,
        casting_ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_lwes_per_compact_list.as_ptr(),
        is_boolean.as_ptr(),
        num_compact_lists as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        casting_key_type as u32,
        true,
        allocate_ms_noise_array,
    );
    cuda_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        lwe_array_out.0.d_vec.as_mut_c_ptr(0),
        lwe_flattened_compact_array_in.as_c_ptr(0),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        computing_ks_key.ptr.as_ptr(),
        casting_key.ptr.as_ptr(),
        &raw const ms_noise_reduction_key_ffi,
    );
    cleanup_expand_without_verification_64(
        streams.ptr.as_ptr(),
        streams.gpu_indexes_ptr(),
        streams.len() as u32,
        std::ptr::addr_of_mut!(mem_ptr),
    );
}
