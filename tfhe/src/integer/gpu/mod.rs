pub mod ciphertext;
pub mod client_key;
pub mod key_switching_key;
pub mod list_compression;
pub mod noise_squashing;
pub mod server_key;
#[cfg(feature = "zk-pok")]
pub mod zk;

use crate::core_crypto::gpu::lwe_bootstrap_key::CudaModulusSwitchNoiseReductionConfiguration;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::slice::{CudaSlice, CudaSliceMut};
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{CudaStreams, PBSMSNoiseReductionType};
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweDimension, Numeric, PolynomialSize, UnsignedInteger,
};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaRadixCiphertext, KsType};
use crate::integer::gpu::list_compression::server_keys::CudaPackedGlweCiphertextList;
use crate::integer::server_key::radix_parallel::scalar_div_mod::{
    choose_multiplier, SignedReciprocable,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::server_key::{MiniUnsignedInteger, Reciprocable, ScalarMultiplier};
use crate::integer::{ClientKey, RadixClientKey};
use crate::prelude::{CastFrom, CastInto};
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

fn resolve_noise_reduction_type(
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> PBSMSNoiseReductionType {
    ms_noise_reduction_configuration.map_or(PBSMSNoiseReductionType::NoReduction, |config| {
        match config {
            CudaModulusSwitchNoiseReductionConfiguration::Centered => {
                PBSMSNoiseReductionType::Centered
            }
        }
    })
}

fn resolve_ms_noise_reduction_config(
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> PBSMSNoiseReductionType {
    ms_noise_reduction_configuration.map_or_else(
        || PBSMSNoiseReductionType::NoReduction,
        |config| match config {
            CudaModulusSwitchNoiseReductionConfiguration::Centered => {
                PBSMSNoiseReductionType::Centered
            }
        },
    )
}

pub(crate) fn prepare_default_scalar_divisor() -> CudaScalarDivisorFFI {
    CudaScalarDivisorFFI {
        decomposed_chosen_multiplier: std::ptr::null(),
        chosen_multiplier_has_at_least_one_set: std::ptr::null(),
        num_scalars: 0,
        active_bits: 0,
        ilog2_chosen_multiplier: 0,
        ilog2_divisor: 0,
        shift_pre: 0,
        shift_post: 0,
        chosen_multiplier_num_bits: 0,
        is_chosen_multiplier_zero: false,
        is_divisor_zero: false,
        is_abs_chosen_multiplier_one: false,
        is_abs_divisor_one: false,
        is_chosen_multiplier_negative: false,
        is_divisor_negative: false,
        is_chosen_multiplier_pow2: false,
        is_divisor_pow2: false,
        chosen_multiplier_has_more_bits_than_numerator: false,
        divisor_has_more_bits_than_numerator: false,
        is_chosen_multiplier_geq_two_pow_numerator: false,
    }
}

fn prepare_cuda_lwe_ct_ffi<T: UnsignedInteger>(
    input: &CudaLweCiphertextList<T>,
) -> CudaLweCiphertextListFFI {
    CudaLweCiphertextListFFI {
        ptr: input.0.d_vec.get_mut_c_ptr(0),
        num_radix_blocks: input.0.lwe_ciphertext_count.0 as u32,
        lwe_dimension: input.0.lwe_dimension.0 as u32,
    }
}

fn prepare_cuda_packed_glwe_ct_ffi<T: UnsignedInteger>(
    input: &CudaPackedGlweCiphertextList<T>,
) -> CudaPackedGlweCiphertextListFFI {
    CudaPackedGlweCiphertextListFFI {
        ptr: input.data.get_mut_c_ptr(0),
        storage_log_modulus: input.meta.unwrap().storage_log_modulus.0 as u32,
        lwe_per_glwe: input.meta.unwrap().lwe_per_glwe.0 as u32,
        total_lwe_bodies_count: input.meta.unwrap().total_lwe_bodies_count as u32,
        glwe_dimension: input.meta.unwrap().glwe_dimension.0 as u32,
        polynomial_size: input.meta.unwrap().polynomial_size.0 as u32,
    }
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

    gen_keys_inner(shortint_parameters_set, streams)
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
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_scalar_addition_assign<T: UnsignedInteger>(
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
    cuda_scalar_addition_ciphertext_64_inplace(
        streams.ffi(),
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
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_mul<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_integer_scalar_mul_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_scalar_multiplication_ciphertext_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_lwe_array,
        decomposed_scalar.as_ptr().cast::<u64>(),
        has_at_least_one_set.as_ptr().cast::<u64>(),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        polynomial_size.0 as u32,
        message_modulus.0 as u32,
        num_scalars,
    );

    cleanup_cuda_scalar_mul(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(lwe_array, &cuda_ffi_lwe_array);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_mul_size_on_gpu<T: UnsignedInteger>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let msg_bits = message_modulus.0.ilog2() as usize;
    let num_ciphertext_bits = msg_bits * num_blocks as usize;
    let num_scalar_bits = decomposed_scalar
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&rhs_bit| rhs_bit == T::ONE)
        .count() as u32;

    let size_tracker = unsafe {
        scratch_cuda_integer_scalar_mul_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_scalar_mul(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_div_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    divisor: Scalar,
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64
where
    Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let numerator_bits = message_modulus.0.ilog2() * num_blocks;
    let msg_bits = message_modulus.0.ilog2() as usize;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
    scalar_divisor_ffi.is_divisor_pow2 = is_divisor_power_of_two;
    scalar_divisor_ffi.is_abs_divisor_one = divisor == Scalar::ONE;
    scalar_divisor_ffi.divisor_has_more_bits_than_numerator =
        MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

    let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

    if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
        && !scalar_divisor_ffi.is_divisor_pow2
        && !scalar_divisor_ffi.divisor_has_more_bits_than_numerator
    {
        let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
        let two_pow_e =
            divisor_dp & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
        let e = MiniUnsignedInteger::ilog2(two_pow_e);
        let divisor_odd_dp = divisor_dp / two_pow_e;

        assert!(numerator_bits > e && e <= Scalar::BITS as u32);
        let divisor_odd: Scalar = divisor_odd_dp.cast_into();
        chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
    }

    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator =
        chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
    } else {
        chosen_multiplier.multiplier
    };

    let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    scalar_divisor_ffi.active_bits = decomposed_rhs
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = unsafe {
        scratch_cuda_integer_unsigned_scalar_div_radix_64(
            streams.ffi(),
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
            &raw const scalar_divisor_ffi,
            false,
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_unsigned_scalar_div_radix_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        )
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_signed_scalar_div_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    divisor: Scalar,
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64
where
    Scalar: SignedReciprocable,
    <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
{
    let numerator_bits = message_modulus.0.ilog2() * num_blocks;
    let msg_bits = message_modulus.0.ilog2() as usize;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
    let chosen_multiplier = choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

    scalar_divisor_ffi.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
    scalar_divisor_ffi.is_divisor_negative = divisor < Scalar::ZERO;
    scalar_divisor_ffi.is_divisor_pow2 = absolute_divisor.is_power_of_two();

    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator = chosen_multiplier.multiplier
        >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
    scalar_divisor_ffi.chosen_multiplier_has_more_bits_than_numerator =
        chosen_multiplier.l >= numerator_bits;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        let cst = chosen_multiplier.multiplier
            - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
        Scalar::DoublePrecision::cast_from(cst)
    } else {
        Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
    };

    let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let num_ciphertext_bits = 2 * msg_bits * num_blocks as usize;
    scalar_divisor_ffi.active_bits = decomposed_rhs
        .iter()
        .take(num_ciphertext_bits)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = unsafe {
        scratch_cuda_integer_signed_scalar_div_radix_64(
            streams.ffi(),
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
            &raw const scalar_divisor_ffi,
            false,
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_signed_scalar_div_radix_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        )
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_compress<
    InputTorus: UnsignedInteger,
    OutputTorus: UnsignedInteger,
>(
    streams: &CudaStreams,
    glwe_array_out: &mut CudaPackedGlweCiphertextList<OutputTorus>,
    lwe_array_in: &CudaLweCiphertextList<InputTorus>,
    fp_keyswitch_key: &CudaVec<OutputTorus>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    lwe_per_glwe: u32,
    num_blocks: u32,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        fp_keyswitch_key.gpu_index(0),
        "GPU error: first stream is on GPU {}, first fp_ksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        fp_keyswitch_key.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array_in.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array_in.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        glwe_array_out.data.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        glwe_array_out.data.gpu_index(0).get(),
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let array_in_ffi = prepare_cuda_lwe_ct_ffi(lwe_array_in);
    let mut glwe_array_out_ffi = prepare_cuda_packed_glwe_ct_ffi(glwe_array_out);

    if TypeId::of::<OutputTorus>() == TypeId::of::<u64>() {
        // 64 bits
        scratch_cuda_integer_compress_radix_ciphertext_64(
            streams.ffi(),
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
            true,
        );

        cuda_integer_compress_radix_ciphertext_64(
            streams.ffi(),
            &raw mut glwe_array_out_ffi,
            &raw const array_in_ffi,
            fp_keyswitch_key.ptr.as_ptr(),
            mem_ptr,
        );

        cleanup_cuda_integer_compress_radix_ciphertext_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    } else if TypeId::of::<OutputTorus>() == TypeId::of::<u128>() {
        // 128 bits
        scratch_cuda_integer_compress_radix_ciphertext_128(
            streams.ffi(),
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
            true,
        );

        cuda_integer_compress_radix_ciphertext_128(
            streams.ffi(),
            &raw mut glwe_array_out_ffi,
            &raw const array_in_ffi,
            fp_keyswitch_key.ptr.as_ptr(),
            mem_ptr,
        );

        cleanup_cuda_integer_compress_radix_ciphertext_128(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_compression_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    ks_base_log: DecompositionBaseLog,
    ks_level: DecompositionLevelCount,
    lwe_per_glwe: u32,
    num_blocks: u32,
) -> u64 {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_compress_radix_ciphertext_64(
            streams.ffi(),
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
            false,
        )
    };

    unsafe {
        cleanup_cuda_integer_compress_radix_ciphertext_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_decompress<B: Numeric>(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaLweCiphertextList<u64>,
    glwe_in: &CudaPackedGlweCiphertextList<u64>,
    bootstrapping_key: &CudaVec<B>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    encryption_glwe_dimension: GlweDimension,
    encryption_polynomial_size: PolynomialSize,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    vec_indexes: &[u32],
    num_blocks_to_decompress: u32,
) {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut lwe_array_out_ffi = prepare_cuda_lwe_ct_ffi(lwe_array_out);
    let glwe_array_in_ffi = prepare_cuda_packed_glwe_ct_ffi(glwe_in);

    scratch_cuda_integer_decompress_radix_ciphertext_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        encryption_glwe_dimension.0 as u32,
        encryption_polynomial_size.0 as u32,
        compression_glwe_dimension.0 as u32,
        compression_polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks_to_decompress,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        PBSMSNoiseReductionType::NoReduction as u32,
    );

    cuda_integer_decompress_radix_ciphertext_64(
        streams.ffi(),
        &raw mut lwe_array_out_ffi,
        &raw const glwe_array_in_ffi,
        vec_indexes.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
        mem_ptr,
    );

    cleanup_cuda_integer_decompress_radix_ciphertext_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
///
///  128-bit decompression doesn't execute a PBS as the 64-bit does.
///  We have a different entry point because we don't need to carry a bsk to the backend.
pub(crate) unsafe fn cuda_backend_decompress_128(
    streams: &CudaStreams,
    lwe_array_out: &mut CudaLweCiphertextList<u128>,
    glwe_in: &CudaPackedGlweCiphertextList<u128>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    vec_indexes: &[u32],
    num_blocks_to_decompress: u32,
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
        glwe_in.data.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        glwe_in.data.gpu_index(0).get(),
    );
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut lwe_array_out_ffi = prepare_cuda_lwe_ct_ffi(lwe_array_out);
    let glwe_array_in_ffi = prepare_cuda_packed_glwe_ct_ffi(glwe_in);

    scratch_cuda_integer_decompress_radix_ciphertext_128(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        compression_glwe_dimension.0 as u32,
        compression_polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        num_blocks_to_decompress,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        true,
    );

    cuda_integer_decompress_radix_ciphertext_128(
        streams.ffi(),
        &raw mut lwe_array_out_ffi,
        &raw const glwe_array_in_ffi,
        vec_indexes.as_ptr(),
        mem_ptr,
    );

    cleanup_cuda_integer_decompress_radix_ciphertext_128(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_decompression_size_on_gpu(
    streams: &CudaStreams,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    encryption_glwe_dimension: GlweDimension,
    encryption_polynomial_size: PolynomialSize,
    compression_glwe_dimension: GlweDimension,
    compression_polynomial_size: PolynomialSize,
    lwe_dimension: LweDimension,
    pbs_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    num_blocks_to_decompress: u32,
) -> u64 {
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_decompress_radix_ciphertext_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
            encryption_glwe_dimension.0 as u32,
            encryption_polynomial_size.0 as u32,
            compression_glwe_dimension.0 as u32,
            compression_polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks_to_decompress,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            PBSMSNoiseReductionType::NoReduction as u32,
        )
    };

    unsafe {
        cleanup_cuda_integer_decompress_radix_ciphertext_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_add_assign(
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
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_mul_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_integer_mult_radix_ciphertext_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_integer_mult_radix_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_left,
        is_boolean_left,
        &raw const cuda_ffi_radix_lwe_right,
        is_boolean_right,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        mem_ptr,
        polynomial_size.0 as u32,
        num_blocks,
    );
    cleanup_cuda_integer_mult(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_mul_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_mult_radix_ciphertext_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_mult(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_bitop_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_bitop_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_bitop_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_integer_bitop(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_bitop_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_bitop_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_bitop(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_bitop_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_bitop_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_scalar_bitop_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe,
        &raw const cuda_ffi_radix_lwe,
        clear_blocks.as_c_ptr(0),
        h_clear_blocks.as_ptr().cast::<std::ffi::c_void>(),
        min(clear_blocks.len() as u32, num_blocks),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_integer_bitop(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe, &cuda_ffi_radix_lwe);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_bitop_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_bitop_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_bitop(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_comparison<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_comparison_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_comparison_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_comparison(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_comparison_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_comparison_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_comparison(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_comparison<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_comparison_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_scalar_comparison_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        scalar_blocks.as_c_ptr(0),
        h_scalar_blocks.as_ptr().cast::<std::ffi::c_void>(),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        num_scalar_blocks,
    );

    cleanup_cuda_integer_comparison(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_full_propagate_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_full_propagation_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
    );
    cleanup_cuda_full_propagation(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_input, &cuda_ffi_radix_lwe_input);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_full_propagate_assign_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_full_propagation_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_full_propagation(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_propagate_single_carry_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_propagate_single_carry_64_inplace(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_propagate_single_carry_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        requested_flag as u32,
        uses_carry,
    );
    cleanup_cuda_propagate_single_carry(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_input, &cuda_ffi_radix_lwe_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_propagate_single_carry_assign_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let size_tracker = unsafe {
        scratch_cuda_propagate_single_carry_64_inplace(
            streams.ffi(),
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
            false,
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_propagate_single_carry(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_add_and_propagate_single_carry_assign_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
    let size_tracker = unsafe {
        scratch_cuda_add_and_propagate_single_carry_64_inplace(
            streams.ffi(),
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
            false,
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_add_and_propagate_single_carry(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_sub_and_propagate_single_carry_assign<
    T: UnsignedInteger,
    B: Numeric,
>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_sub_and_propagate_single_carry_64_inplace(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_sub_and_propagate_single_carry_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_lhs_input,
        &raw const cuda_ffi_rhs_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        requested_flag as u32,
        uses_carry,
    );

    cleanup_cuda_sub_and_propagate_single_carry(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(lhs_input, &cuda_ffi_lhs_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_add_and_propagate_single_carry_assign<
    T: UnsignedInteger,
    B: Numeric,
>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_add_and_propagate_single_carry_64_inplace(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_add_and_propagate_single_carry_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_lhs_input,
        &raw const cuda_ffi_rhs_input,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        requested_flag as u32,
        uses_carry,
    );
    cleanup_cuda_add_and_propagate_single_carry(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(lhs_input, &cuda_ffi_lhs_input);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_grouped_oprf<B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    seeded_lwe_input: &CudaVec<u64>,
    num_blocks_to_process: u32,
    bootstrapping_key: &CudaVec<B>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    message_bits_per_block: u32,
    total_random_bits: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
    );
    assert_eq!(streams.gpu_indexes[0], seeded_lwe_input.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bootstrapping_key.gpu_index(0),);

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.get())
        .collect();
    let mut out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out =
        prepare_cuda_radix_ffi(radix_lwe_out, &mut out_degrees, &mut out_noise_levels);

    scratch_cuda_integer_grouped_oprf_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks_to_process,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        message_bits_per_block,
        total_random_bits,
        noise_reduction_type as u32,
    );

    cuda_integer_grouped_oprf_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        seeded_lwe_input.as_c_ptr(0),
        num_blocks_to_process,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_grouped_oprf_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_grouped_oprf_custom_range<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    radix_lwe_out: &mut CudaRadixCiphertext,
    num_blocks_intermediate: u32,
    seeded_lwe_input: &CudaVec<u64>,
    decomposed_scalar: &[T],
    has_at_least_one_set: &[T],
    shift: u32,
    bootstrapping_key: &CudaVec<B>,
    key_switching_key: &CudaVec<u64>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    message_bits_per_block: u32,
    _total_random_bits: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        radix_lwe_out.d_blocks.0.d_vec.gpu_index(0),
    );
    assert_eq!(streams.gpu_indexes[0], seeded_lwe_input.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bootstrapping_key.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], key_switching_key.gpu_index(0));

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let num_scalars = decomposed_scalar.len() as u32;

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut out_degrees = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.degree.get())
        .collect();
    let mut out_noise_levels = radix_lwe_out
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_radix_lwe_out =
        prepare_cuda_radix_ffi(radix_lwe_out, &mut out_degrees, &mut out_noise_levels);

    scratch_cuda_integer_grouped_oprf_custom_range_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        num_blocks_intermediate,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        message_bits_per_block,
        shift,
        num_scalars,
        noise_reduction_type as u32,
    );

    cuda_integer_grouped_oprf_custom_range_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        num_blocks_intermediate,
        seeded_lwe_input.as_c_ptr(0),
        decomposed_scalar.as_ptr().cast::<u64>(),
        has_at_least_one_set.as_ptr().cast::<u64>(),
        num_scalars,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        key_switching_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_grouped_oprf_custom_range_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_grouped_oprf_size_on_gpu(
    streams: &CudaStreams,
    num_blocks_to_process: u32,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    message_bits_per_block: u32,
    total_random_bits: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = unsafe {
        scratch_cuda_integer_grouped_oprf_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            num_blocks_to_process,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            message_bits_per_block,
            total_random_bits,
            noise_reduction_type as u32,
        )
    };

    unsafe { cleanup_cuda_integer_grouped_oprf_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr)) };

    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_unsigned_scalar_div_rem<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    quotient: &mut CudaRadixCiphertext,
    remainder: &mut CudaRadixCiphertext,
    divisor: Scalar,
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) where
    Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let num_blocks = quotient.d_blocks.lwe_ciphertext_count().0 as u32;
    let msg_bits = message_modulus.0.ilog2() as usize;
    let numerator_bits = msg_bits as u32 * num_blocks;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
    let log2_divisor_exceeds_threshold = MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;
    let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

    let shift_pre = if chosen_multiplier.multiplier
        >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
        && !is_divisor_power_of_two
        && !log2_divisor_exceeds_threshold
    {
        let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
        let two_pow_e =
            divisor_dp & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
        let e = MiniUnsignedInteger::ilog2(two_pow_e);
        let divisor_odd_dp = divisor_dp / two_pow_e;

        assert!(numerator_bits > e && e <= Scalar::BITS as u32);
        let divisor_odd: Scalar = divisor_odd_dp.cast_into();
        chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
        e as u64
    } else {
        0
    };

    scalar_divisor_ffi.shift_pre = shift_pre;
    scalar_divisor_ffi.shift_post = chosen_multiplier.shift_post;
    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator =
        chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);
    scalar_divisor_ffi.chosen_multiplier_num_bits = chosen_multiplier.l;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
    } else {
        chosen_multiplier.multiplier
    };

    let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let decomposer_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
    let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer_rhs.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            multiplier_has_at_least_one_set[i % msg_bits] = 1;
        }
    }

    scalar_divisor_ffi.decomposed_chosen_multiplier = decomposed_multiplier.as_ptr();
    scalar_divisor_ffi.chosen_multiplier_has_at_least_one_set =
        multiplier_has_at_least_one_set.as_ptr();
    scalar_divisor_ffi.num_scalars = decomposed_multiplier.len() as u32;
    scalar_divisor_ffi.active_bits = decomposed_multiplier
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;
    scalar_divisor_ffi.is_chosen_multiplier_pow2 = MiniUnsignedInteger::is_power_of_two(rhs);
    scalar_divisor_ffi.is_abs_chosen_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
    scalar_divisor_ffi.is_chosen_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
    scalar_divisor_ffi.ilog2_chosen_multiplier = if scalar_divisor_ffi.is_chosen_multiplier_pow2 {
        MiniUnsignedInteger::ilog2(rhs)
    } else {
        0
    };

    let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let decomposer_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();
    let mut divisor_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer_divisor.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            divisor_has_at_least_one_set[i % msg_bits] = 1;
        }
    }

    scalar_divisor_ffi.is_divisor_pow2 = is_divisor_power_of_two;
    scalar_divisor_ffi.is_abs_divisor_one = divisor == Scalar::ONE;
    scalar_divisor_ffi.ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);
    scalar_divisor_ffi.divisor_has_more_bits_than_numerator = log2_divisor_exceeds_threshold;

    let h_clear_blocks =
        BlockDecomposer::with_early_stop_at_zero(divisor - Scalar::ONE, message_modulus.0.ilog2())
            .iter_as::<u64>()
            .collect::<Vec<_>>();
    let clear_blocks = CudaVec::from_cpu_async(&h_clear_blocks, streams, 0);

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    let num_scalars_divisor = decomposed_divisor.len() as u32;
    let active_bits_divisor = decomposed_divisor
        .iter()
        .take(msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    scratch_integer_unsigned_scalar_div_rem_radix_64(
        streams.ffi(),
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
        &raw const scalar_divisor_ffi,
        active_bits_divisor,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_unsigned_scalar_div_rem_radix_64(
        streams.ffi(),
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        mem_ptr,
        bsks.ptr.as_ptr(),
        ksks.ptr.as_ptr(),
        &raw const scalar_divisor_ffi,
        divisor_has_at_least_one_set.as_ptr(),
        decomposed_divisor.as_ptr(),
        num_scalars_divisor,
        clear_blocks.as_c_ptr(0),
        h_clear_blocks.as_ptr().cast::<std::ffi::c_void>(),
        min(clear_blocks.len() as u32, num_blocks),
    );

    cleanup_cuda_integer_unsigned_scalar_div_rem_radix_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_signed_scalar_div_rem_assign<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    quotient: &mut CudaRadixCiphertext,
    remainder: &mut CudaRadixCiphertext,
    divisor: Scalar,
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) where
    Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
{
    let num_blocks = quotient.d_blocks.lwe_ciphertext_count().0 as u32;
    let msg_bits = message_modulus.0.ilog2() as usize;
    let numerator_bits = msg_bits as u32 * num_blocks;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
    let chosen_multiplier = choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

    let is_abs_divisor_pow2 = absolute_divisor.is_power_of_two();
    scalar_divisor_ffi.is_divisor_pow2 = is_abs_divisor_pow2;
    scalar_divisor_ffi.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
    scalar_divisor_ffi.is_divisor_negative = divisor < Scalar::ZERO;
    scalar_divisor_ffi.is_divisor_zero = divisor == Scalar::ZERO;
    if is_abs_divisor_pow2 && !scalar_divisor_ffi.is_divisor_negative {
        scalar_divisor_ffi.ilog2_divisor = divisor.ilog2();
    }

    let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let decomposer_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1).iter_as::<u8>();
    let mut divisor_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer_divisor.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            divisor_has_at_least_one_set[i % msg_bits] = 1;
        }
    }

    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator = chosen_multiplier.multiplier
        >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
    scalar_divisor_ffi.chosen_multiplier_num_bits = chosen_multiplier.l;
    scalar_divisor_ffi.shift_post = chosen_multiplier.shift_post;
    scalar_divisor_ffi.chosen_multiplier_has_more_bits_than_numerator =
        chosen_multiplier.l >= numerator_bits;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        let cst = chosen_multiplier.multiplier
            - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
        Scalar::DoublePrecision::cast_from(cst)
    } else {
        Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
    };

    let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
    let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer_rhs.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            multiplier_has_at_least_one_set[i % msg_bits] = 1;
        }
    }
    scalar_divisor_ffi.chosen_multiplier_has_at_least_one_set =
        multiplier_has_at_least_one_set.as_ptr();
    scalar_divisor_ffi.decomposed_chosen_multiplier = decomposed_multiplier.as_ptr();
    scalar_divisor_ffi.num_scalars = decomposed_multiplier.len() as u32;
    scalar_divisor_ffi.active_bits = decomposed_multiplier
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    scalar_divisor_ffi.is_chosen_multiplier_pow2 = rhs.is_power_of_two();
    scalar_divisor_ffi.is_abs_chosen_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
    scalar_divisor_ffi.is_chosen_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
    scalar_divisor_ffi.ilog2_chosen_multiplier = if scalar_divisor_ffi.is_chosen_multiplier_pow2
        && !scalar_divisor_ffi.is_abs_chosen_multiplier_one
    {
        rhs.ilog2()
    } else {
        0u32
    };

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    let num_scalars_divisor = decomposed_divisor.len() as u32;
    let active_bits_divisor = decomposed_divisor
        .iter()
        .take(message_modulus.0.ilog2() as usize * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    scratch_integer_signed_scalar_div_rem_radix_64(
        streams.ffi(),
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
        &raw const scalar_divisor_ffi,
        active_bits_divisor,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_signed_scalar_div_rem_radix_64(
        streams.ffi(),
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        mem_ptr,
        bsks.ptr.as_ptr(),
        ksks.ptr.as_ptr(),
        &raw const scalar_divisor_ffi,
        divisor_has_at_least_one_set.as_ptr(),
        decomposed_divisor.as_ptr(),
        num_scalars_divisor,
        numerator_bits,
    );

    cleanup_cuda_integer_signed_scalar_div_rem_radix_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_div_rem_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    divisor: Scalar,
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64
where
    Scalar: Reciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
{
    let numerator_bits = message_modulus.0.ilog2() * num_blocks;
    let msg_bits = message_modulus.0.ilog2() as usize;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
    scalar_divisor_ffi.is_divisor_pow2 = is_divisor_power_of_two;
    scalar_divisor_ffi.is_abs_divisor_one = divisor == Scalar::ONE;
    scalar_divisor_ffi.divisor_has_more_bits_than_numerator =
        MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

    let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let active_bits_divisor = decomposed_divisor
        .iter()
        .take(msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

    if chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
        && !scalar_divisor_ffi.is_divisor_pow2
        && !scalar_divisor_ffi.divisor_has_more_bits_than_numerator
    {
        let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
        let two_pow_e =
            divisor_dp & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
        let e = MiniUnsignedInteger::ilog2(two_pow_e);
        let divisor_odd_dp = divisor_dp / two_pow_e;

        assert!(numerator_bits > e && e <= Scalar::BITS as u32);
        let divisor_odd: Scalar = divisor_odd_dp.cast_into();
        chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
    }

    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator =
        chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
    } else {
        chosen_multiplier.multiplier
    };

    let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    scalar_divisor_ffi.active_bits = decomposed_rhs
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = unsafe {
        scratch_integer_unsigned_scalar_div_rem_radix_64(
            streams.ffi(),
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
            &raw const scalar_divisor_ffi,
            active_bits_divisor,
            false,
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_integer_unsigned_scalar_div_rem_radix_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_signed_scalar_div_rem_size_on_gpu<Scalar>(
    streams: &CudaStreams,
    divisor: Scalar,
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64
where
    Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
{
    let numerator_bits = message_modulus.0.ilog2() * num_blocks;
    let msg_bits = message_modulus.0.ilog2() as usize;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
    scalar_divisor_ffi.is_divisor_pow2 = absolute_divisor.is_power_of_two();
    scalar_divisor_ffi.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
    scalar_divisor_ffi.is_divisor_negative = divisor < Scalar::ZERO;
    scalar_divisor_ffi.is_divisor_zero = divisor == Scalar::ZERO;

    let decomposed_divisor = BlockDecomposer::with_early_stop_at_zero(divisor, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    let active_bits_divisor = decomposed_divisor
        .iter()
        .take(msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    let chosen_multiplier = choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);
    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator = chosen_multiplier.multiplier
        >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
    scalar_divisor_ffi.chosen_multiplier_has_more_bits_than_numerator =
        chosen_multiplier.l >= numerator_bits;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        let cst = chosen_multiplier.multiplier
            - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
        Scalar::DoublePrecision::cast_from(cst)
    } else {
        Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
    };
    let decomposed_rhs = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();
    scalar_divisor_ffi.active_bits = decomposed_rhs
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let size_tracker = unsafe {
        scratch_integer_signed_scalar_div_rem_radix_64(
            streams.ffi(),
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
            &raw const scalar_divisor_ffi,
            active_bits_divisor,
            false,
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_integer_signed_scalar_div_rem_radix_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_unsigned_scalar_div_assign<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    numerator: &mut CudaRadixCiphertext,
    divisor: Scalar,
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) where
    Scalar: Reciprocable,
{
    assert_eq!(
        streams.gpu_indexes[0],
        numerator.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(streams.gpu_indexes[0], ksks.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], bsks.gpu_index(0));

    let num_blocks = numerator.d_blocks.lwe_ciphertext_count().0 as u32;

    let numerator_bits = message_modulus.0.ilog2() * num_blocks;
    let msg_bits = message_modulus.0.ilog2() as usize;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let is_divisor_power_of_two = MiniUnsignedInteger::is_power_of_two(divisor);
    scalar_divisor_ffi.is_divisor_pow2 = is_divisor_power_of_two;
    scalar_divisor_ffi.is_abs_divisor_one = divisor == Scalar::ONE;
    scalar_divisor_ffi.ilog2_divisor = MiniUnsignedInteger::ilog2(divisor);
    scalar_divisor_ffi.divisor_has_more_bits_than_numerator =
        MiniUnsignedInteger::ceil_ilog2(divisor) > numerator_bits;

    let mut chosen_multiplier = choose_multiplier(divisor, numerator_bits, numerator_bits);

    let shift_pre = if chosen_multiplier.multiplier
        >= (Scalar::DoublePrecision::ONE << numerator_bits as usize)
        && crate::integer::server_key::radix_parallel::scalar_div_mod::is_even(divisor)
        && !is_divisor_power_of_two
        && !scalar_divisor_ffi.divisor_has_more_bits_than_numerator
    {
        let divisor_dp = Scalar::DoublePrecision::cast_from(divisor);
        let two_pow_e =
            divisor_dp & ((Scalar::DoublePrecision::ONE << numerator_bits as usize) - divisor_dp);
        let e = MiniUnsignedInteger::ilog2(two_pow_e);
        let divisor_odd_dp = divisor_dp / two_pow_e;

        assert!(numerator_bits > e && e <= Scalar::BITS as u32);
        let divisor_odd: Scalar = divisor_odd_dp.cast_into();
        chosen_multiplier = choose_multiplier(divisor_odd, numerator_bits - e, numerator_bits);
        e as u64
    } else {
        0
    };

    scalar_divisor_ffi.shift_pre = shift_pre;
    scalar_divisor_ffi.shift_post = chosen_multiplier.shift_post;
    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator =
        chosen_multiplier.multiplier >= (Scalar::DoublePrecision::ONE << numerator_bits as usize);
    scalar_divisor_ffi.chosen_multiplier_num_bits = chosen_multiplier.l;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        chosen_multiplier.multiplier - (Scalar::DoublePrecision::ONE << numerator_bits as usize)
    } else {
        chosen_multiplier.multiplier
    };

    let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();

    let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            multiplier_has_at_least_one_set[i % msg_bits] = 1;
        }
    }
    scalar_divisor_ffi.chosen_multiplier_has_at_least_one_set =
        multiplier_has_at_least_one_set.as_ptr();
    scalar_divisor_ffi.decomposed_chosen_multiplier = decomposed_multiplier.as_ptr();
    scalar_divisor_ffi.num_scalars = decomposed_multiplier.len() as u32;
    scalar_divisor_ffi.active_bits = decomposed_multiplier
        .iter()
        .take(2 * msg_bits * num_blocks as usize)
        .filter(|&&rhs_bit| rhs_bit == 1u64)
        .count() as u32;

    scalar_divisor_ffi.is_chosen_multiplier_pow2 = MiniUnsignedInteger::is_power_of_two(rhs);
    scalar_divisor_ffi.is_abs_chosen_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
    scalar_divisor_ffi.is_chosen_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;

    scalar_divisor_ffi.ilog2_chosen_multiplier = if scalar_divisor_ffi.is_chosen_multiplier_pow2
        && !scalar_divisor_ffi.is_abs_chosen_multiplier_one
    {
        MiniUnsignedInteger::ilog2(rhs)
    } else {
        0u32
    };

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_integer_unsigned_scalar_div_radix_64(
        streams.ffi(),
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
        &raw const scalar_divisor_ffi,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_unsigned_scalar_div_radix_64(
        streams.ffi(),
        &raw mut cuda_ffi_numerator,
        mem_ptr,
        bsks.ptr.as_ptr(),
        ksks.ptr.as_ptr(),
        &raw const scalar_divisor_ffi,
    );

    cleanup_cuda_integer_unsigned_scalar_div_radix_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(numerator, &cuda_ffi_numerator);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_signed_scalar_div_assign<
    T: UnsignedInteger,
    B: Numeric,
    Scalar,
>(
    streams: &CudaStreams,
    numerator: &mut CudaRadixCiphertext,
    divisor: Scalar,
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) where
    Scalar: SignedReciprocable + ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
    <<Scalar as SignedReciprocable>::Unsigned as Reciprocable>::DoublePrecision: Send,
{
    let num_blocks = numerator.d_blocks.lwe_ciphertext_count().0 as u32;
    let msg_bits = message_modulus.0.ilog2() as usize;
    let numerator_bits = msg_bits as u32 * num_blocks;

    let mut scalar_divisor_ffi = prepare_default_scalar_divisor();

    let absolute_divisor = Scalar::Unsigned::cast_from(divisor.wrapping_abs());
    let chosen_multiplier = choose_multiplier(absolute_divisor, numerator_bits - 1, numerator_bits);

    scalar_divisor_ffi.is_abs_divisor_one = absolute_divisor == Scalar::Unsigned::ONE;
    scalar_divisor_ffi.is_divisor_negative = divisor < Scalar::ZERO;
    scalar_divisor_ffi.is_divisor_pow2 = absolute_divisor.is_power_of_two();

    scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator = chosen_multiplier.multiplier
        >= (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << (numerator_bits - 1));
    scalar_divisor_ffi.shift_post = chosen_multiplier.shift_post;
    scalar_divisor_ffi.chosen_multiplier_num_bits = chosen_multiplier.l;
    scalar_divisor_ffi.chosen_multiplier_has_more_bits_than_numerator =
        chosen_multiplier.l >= numerator_bits;

    let rhs = if scalar_divisor_ffi.is_chosen_multiplier_geq_two_pow_numerator {
        let cst = chosen_multiplier.multiplier
            - (<Scalar::Unsigned as Reciprocable>::DoublePrecision::ONE << numerator_bits);
        Scalar::DoublePrecision::cast_from(cst)
    } else {
        Scalar::DoublePrecision::cast_from(chosen_multiplier.multiplier)
    };

    let decomposed_multiplier = BlockDecomposer::with_early_stop_at_zero(rhs, 1)
        .iter_as::<u64>()
        .collect::<Vec<_>>();

    let decomposer = BlockDecomposer::with_early_stop_at_zero(rhs, 1).iter_as::<u8>();
    let mut multiplier_has_at_least_one_set = vec![0u64; msg_bits];
    for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
        if bit == 1 {
            multiplier_has_at_least_one_set[i % msg_bits] = 1;
        }
    }
    scalar_divisor_ffi.chosen_multiplier_has_at_least_one_set =
        multiplier_has_at_least_one_set.as_ptr();
    scalar_divisor_ffi.decomposed_chosen_multiplier = decomposed_multiplier.as_ptr();
    scalar_divisor_ffi.num_scalars = decomposed_multiplier.len() as u32;
    scalar_divisor_ffi.active_bits = decomposed_multiplier
        .iter()
        .take(msg_bits * 2 * num_blocks as usize)
        .filter(|&&bit| bit == 1u64)
        .count() as u32;

    scalar_divisor_ffi.is_chosen_multiplier_pow2 = rhs.is_power_of_two();
    scalar_divisor_ffi.is_abs_chosen_multiplier_one = rhs == Scalar::DoublePrecision::ONE;
    scalar_divisor_ffi.is_chosen_multiplier_zero = rhs == Scalar::DoublePrecision::ZERO;
    scalar_divisor_ffi.ilog2_chosen_multiplier = if scalar_divisor_ffi.is_chosen_multiplier_pow2 {
        rhs.ilog2()
    } else {
        0u32
    };

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_integer_signed_scalar_div_radix_64(
        streams.ffi(),
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
        &raw const scalar_divisor_ffi,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_signed_scalar_div_radix_64(
        streams.ffi(),
        &raw mut cuda_ffi_numerator,
        mem_ptr,
        bsks.ptr.as_ptr(),
        ksks.ptr.as_ptr(),
        &raw const scalar_divisor_ffi,
        numerator_bits,
    );

    cleanup_cuda_integer_signed_scalar_div_radix_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(numerator, &cuda_ffi_numerator);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_left_shift_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_logical_scalar_shift_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_logical_scalar_shift_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_logical_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_logical_right_shift_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_logical_scalar_shift_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_logical_scalar_shift_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_logical_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_arithmetic_right_shift_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut radix_lwe_left_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut radix_lwe_left_noise_levels =
        input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_radix_lwe_left = prepare_cuda_radix_ffi(
        input,
        &mut radix_lwe_left_degrees,
        &mut radix_lwe_left_noise_levels,
    );

    scratch_cuda_arithmetic_scalar_shift_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_arithmetic_scalar_shift_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_arithmetic_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_right_shift_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_shift_and_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_shift_and_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_left_shift_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_shift_and_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_shift_and_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_rotate_right_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_shift_and_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_shift_and_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_rotate_left_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_shift_and_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_shift_and_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_shift,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_left_shift_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_logical_scalar_shift_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_logical_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_logical_right_shift_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_logical_scalar_shift_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_logical_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_arithmetic_scalar_shift_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_arithmetic_scalar_shift(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_right_shift_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_shift_and_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_left_shift_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_shift_and_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_rotate_right_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_shift_and_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_rotate_left_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_shift_and_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_shift_and_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_cmux<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_cmux_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_cmux_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_condition,
        &raw const cuda_ffi_radix_lwe_true,
        &raw const cuda_ffi_radix_lwe_false,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_cmux(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_rerand_assign<T: UnsignedInteger>(
    streams: &CudaStreams,
    lwe_array: &mut CudaLweCiphertextList<T>,
    zero_lwes: &CudaLweCompactCiphertextList<T>,
    keyswitch_key: &CudaLweKeyswitchKey<T>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    big_lwe_dimension: LweDimension,
    small_lwe_dimension: LweDimension,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    num_blocks: u32,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_array.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_array.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        zero_lwes.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        zero_lwes.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        keyswitch_key.d_vec.gpu_index(0).get(),
    );

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_rerand_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        big_lwe_dimension.0 as u32,
        small_lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        true,
    );
    cuda_rerand_64(
        streams.ffi(),
        lwe_array.0.d_vec.as_mut_c_ptr(0),
        zero_lwes.0.d_vec.as_c_ptr(0),
        mem_ptr,
        keyswitch_key.d_vec.ptr.as_ptr(),
    );
    cleanup_cuda_rerand(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_cmux_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_cmux_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_cmux(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_rotate_left_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_scalar_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_scalar_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        n,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_scalar_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_scalar_rotate_right_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_scalar_rotate_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_scalar_rotate_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        n,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_scalar_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_input, &cuda_ffi_radix_lwe_left);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_scalar_rotate_left_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_scalar_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_scalar_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn get_scalar_rotate_right_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_scalar_rotate_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_scalar_rotate(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_partial_sum_ciphertexts_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_partial_sum_ciphertexts_vec_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_partial_sum_ciphertexts_vec_64(
        streams.ffi(),
        &raw mut cuda_ffi_result,
        &raw mut cuda_ffi_radix_list,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_partial_sum_ciphertexts_vec(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(result, &cuda_ffi_result);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_extend_radix_with_sign_msb<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let message_modulus = ct.info.blocks.first().unwrap().message_modulus;
    let carry_modulus = ct.info.blocks.first().unwrap().carry_modulus;

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_extend_radix_with_sign_msb_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_output,
        &raw const cuda_ffi_radix_input,
        mem_ptr,
        num_additional_blocks,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_extend_radix_with_sign_msb_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(output, &cuda_ffi_radix_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_apply_univariate_lut<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_apply_univariate_lut_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_apply_univariate_lut_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
    );
    cleanup_cuda_apply_univariate_lut_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_apply_many_univariate_lut<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_apply_many_univariate_lut_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_apply_many_univariate_lut_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
        num_many_lut,
        lut_stride,
    );
    cleanup_cuda_apply_univariate_lut_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_apply_bivariate_lut<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_apply_bivariate_lut_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_apply_bivariate_lut_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input_1,
        &raw const cuda_ffi_input_2,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
        shift,
    );
    cleanup_cuda_apply_bivariate_lut_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_div_rem_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_integer_div_rem_radix_ciphertext_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_integer_div_rem_radix_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_quotient,
        &raw mut cuda_ffi_remainder,
        &raw const cuda_ffi_numerator,
        &raw const cuda_ffi_divisor,
        is_signed,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_integer_div_rem(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(quotient, &cuda_ffi_quotient);
    update_noise_degree(remainder, &cuda_ffi_remainder);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_div_rem_size_on_gpu(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size_tracker = unsafe {
        scratch_cuda_integer_div_rem_radix_ciphertext_64(
            streams.ffi(),
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
            noise_reduction_type as u32,
        )
    };
    unsafe {
        cleanup_cuda_integer_div_rem(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    }
    size_tracker
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_count_of_consecutive_bits<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output_ct: &mut CudaRadixCiphertext,
    input_ct: &CudaRadixCiphertext,
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
    direction: Direction,
    bit_value: BitValue,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    assert_eq!(
        streams.gpu_indexes[0],
        output_ct.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: stream and output ct are on different GPUs"
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_ct.d_blocks.0.d_vec.gpu_index(0),
        "GPU error: stream and input ct are on different GPUs"
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bootstrapping_key.gpu_index(0),
        "GPU error: stream and bootstrapping_key are on different GPUs"
    );
    assert_eq!(
        streams.gpu_indexes[0],
        keyswitch_key.gpu_index(0),
        "GPU error: stream and keyswitch_key are on different GPUs"
    );

    let num_blocks = input_ct.d_blocks.lwe_ciphertext_count().0 as u32;
    let counter_num_blocks = output_ct.d_blocks.lwe_ciphertext_count().0 as u32;

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut output_degrees = output_ct.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output_ct
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_output_ct =
        prepare_cuda_radix_ffi(output_ct, &mut output_degrees, &mut output_noise_levels);

    let mut input_degrees = input_ct.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut input_noise_levels = input_ct
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_input_ct =
        prepare_cuda_radix_ffi(input_ct, &mut input_degrees, &mut input_noise_levels);

    scratch_integer_count_of_consecutive_bits_64(
        streams.ffi(),
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
        counter_num_blocks,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        direction,
        bit_value,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_count_of_consecutive_bits_64(
        streams.ffi(),
        &raw mut cuda_ffi_output_ct,
        &raw const cuda_ffi_input_ct,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_count_of_consecutive_bits_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );

    update_noise_degree(output_ct, &cuda_ffi_output_ct);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_ilog2<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaRadixCiphertext,
    input: &CudaRadixCiphertext,
    trivial_ct_neg_n: &CudaRadixCiphertext,
    trivial_ct_2: &CudaRadixCiphertext,
    trivial_ct_m_minus_1_block: &CudaRadixCiphertext,
    bootstrapping_key: &CudaVec<B>,
    keyswitch_key: &CudaVec<T>,
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    ks_level: DecompositionLevelCount,
    ks_base_log: DecompositionBaseLog,
    pbs_level: DecompositionLevelCount,
    pbs_base_log: DecompositionBaseLog,
    grouping_factor: LweBskGroupingFactor,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    pbs_type: PBSType,
    input_num_blocks: u32,
    counter_num_blocks: u32,
    num_bits_in_ciphertext: u32,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    assert_eq!(streams.gpu_indexes[0], output.d_blocks.0.d_vec.gpu_index(0));
    assert_eq!(streams.gpu_indexes[0], input.d_blocks.0.d_vec.gpu_index(0));
    assert_eq!(
        streams.gpu_indexes[0],
        trivial_ct_neg_n.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(
        streams.gpu_indexes[0],
        trivial_ct_2.d_blocks.0.d_vec.gpu_index(0)
    );
    assert_eq!(
        streams.gpu_indexes[0],
        trivial_ct_m_minus_1_block.d_blocks.0.d_vec.gpu_index(0)
    );

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();

    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    let mut input_degrees = input.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut input_noise_levels = input.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_input = prepare_cuda_radix_ffi(input, &mut input_degrees, &mut input_noise_levels);

    let mut trivial_ct_neg_n_degrees = trivial_ct_neg_n
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut trivial_ct_neg_n_noise_levels = trivial_ct_neg_n
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_trivial_ct_neg_n = prepare_cuda_radix_ffi(
        trivial_ct_neg_n,
        &mut trivial_ct_neg_n_degrees,
        &mut trivial_ct_neg_n_noise_levels,
    );

    let mut trivial_ct_2_degrees = trivial_ct_2
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut trivial_ct_2_noise_levels = trivial_ct_2
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_trivial_ct_2 = prepare_cuda_radix_ffi(
        trivial_ct_2,
        &mut trivial_ct_2_degrees,
        &mut trivial_ct_2_noise_levels,
    );

    let mut trivial_all_ones_block_degrees = trivial_ct_m_minus_1_block
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut trivial_all_ones_block_noise_levels = trivial_ct_m_minus_1_block
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_trivial_all_ones_block = prepare_cuda_radix_ffi(
        trivial_ct_m_minus_1_block,
        &mut trivial_all_ones_block_degrees,
        &mut trivial_all_ones_block_noise_levels,
    );

    scratch_integer_ilog2_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        input_num_blocks,
        counter_num_blocks,
        num_bits_in_ciphertext,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_ilog2_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        &raw const cuda_ffi_trivial_ct_neg_n,
        &raw const cuda_ffi_trivial_ct_2,
        &raw const cuda_ffi_trivial_all_ones_block,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_ilog2_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(output, &cuda_ffi_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_compute_prefix_sum_hillis_steele<
    T: UnsignedInteger,
    B: Numeric,
>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw mut cuda_ffi_generates_or_propagates,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
        num_blocks,
    );

    cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_unsigned_overflowing_sub_assign<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_integer_overflowing_sub_64_inplace(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_integer_overflowing_sub_64_inplace(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_left,
        &raw const cuda_ffi_radix_lwe_right,
        &raw mut cuda_ffi_carry_out,
        &raw const cuda_ffi_carry_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        compute_overflow as u32,
        uses_input_borrow,
    );
    cleanup_cuda_integer_overflowing_sub(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(radix_lwe_left, &cuda_ffi_radix_lwe_left);
    update_noise_degree(carry_out, &cuda_ffi_carry_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_signed_abs_assign<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let mut ct_degrees = ct.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut ct_noise_levels = ct.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_ct = prepare_cuda_radix_ffi(ct, &mut ct_degrees, &mut ct_noise_levels);
    scratch_cuda_integer_abs_inplace_radix_ciphertext_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_integer_abs_inplace_radix_ciphertext_64(
        streams.ffi(),
        &raw mut cuda_ffi_ct,
        mem_ptr,
        true,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );
    cleanup_cuda_integer_abs_inplace(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
    update_noise_degree(ct, &cuda_ffi_ct);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_is_at_least_one_comparisons_block_true<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_integer_is_at_least_one_comparisons_block_true_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_integer_is_at_least_one_comparisons_block_true_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
    );

    cleanup_cuda_integer_is_at_least_one_comparisons_block_true(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_are_all_comparisons_block_true<
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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
    scratch_cuda_integer_are_all_comparisons_block_true_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_integer_are_all_comparisons_block_true_64(
        streams.ffi(),
        &raw mut cuda_ffi_radix_lwe_out,
        &raw const cuda_ffi_radix_lwe_in,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
        radix_lwe_in.d_blocks.lwe_ciphertext_count().0 as u32,
    );

    cleanup_cuda_integer_are_all_comparisons_block_true(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
    );
    update_noise_degree(radix_lwe_out, &cuda_ffi_radix_lwe_out);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_negate(
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

    cuda_negate_ciphertext_64(
        streams.ffi(),
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
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_trim_radix_blocks_lsb(
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
        streams.ffi(),
    );
    update_noise_degree(output, &cuda_ffi_output);
}

/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_extend_radix_with_trivial_zero_blocks_msb(
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
        streams.ffi(),
    );

    update_noise_degree(output, &cuda_ffi_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_noise_squashing<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaSliceMut<T>,
    output_degrees: &mut Vec<u64>,
    output_noise_levels: &mut Vec<u64>,
    input: &CudaSlice<u64>,
    bootstrapping_key: &CudaVec<B>,
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

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

    scratch_cuda_apply_noise_squashing(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );

    cuda_apply_noise_squashing(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_input,
        mem_ptr,
        keyswitch_key.ptr.as_ptr(),
        bootstrapping_key.ptr.as_ptr(),
    );

    cleanup_cuda_apply_noise_squashing(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
///
///
/// In this method, the input `lwe_flattened_compact_array_in` represents a flattened compact list.
/// Instead of receiving a `Vec<CompactCiphertextList>`, it takes a concatenation of all LWEs
/// that were inside that vector of compact list. Handling the input this way removes the need
/// to process multiple compact lists separately, simplifying GPU-based operations. The variable
/// name `lwe_flattened_compact_array_in` makes this intent explicit.
pub(crate) unsafe fn cuda_backend_expand<T: UnsignedInteger, B: Numeric>(
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
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
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
    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let num_compact_lists = num_lwes_per_compact_list.len();

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    scratch_cuda_expand_without_verification_64(
        streams.ffi(),
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
        noise_reduction_type as u32,
    );
    cuda_expand_without_verification_64(
        streams.ffi(),
        lwe_array_out.0.d_vec.as_mut_c_ptr(0),
        lwe_flattened_compact_array_in.as_c_ptr(0),
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        computing_ks_key.ptr.as_ptr(),
        casting_key.ptr.as_ptr(),
    );
    cleanup_expand_without_verification_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_aes_ctr_encrypt<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaRadixCiphertext,
    iv: &CudaRadixCiphertext,
    round_keys: &CudaRadixCiphertext,
    start_counter: u128,
    num_aes_inputs: u32,
    sbox_parallelism: u32,
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
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    let mut iv_degrees = iv.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut iv_noise_levels = iv.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_iv = prepare_cuda_radix_ffi(iv, &mut iv_degrees, &mut iv_noise_levels);

    let mut round_keys_degrees = round_keys.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut round_keys_noise_levels = round_keys
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_round_keys = prepare_cuda_radix_ffi(
        round_keys,
        &mut round_keys_degrees,
        &mut round_keys_noise_levels,
    );

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let counter_bits_le: Vec<u64> = (0..num_aes_inputs)
        .flat_map(|i| {
            let current_counter = start_counter + i as u128;
            (0..128).map(move |bit_index| ((current_counter >> bit_index) & 1) as u64)
        })
        .collect();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_aes_encrypt_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        noise_reduction_type as u32,
        num_aes_inputs,
        sbox_parallelism,
    );

    cuda_integer_aes_ctr_encrypt_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_iv,
        &raw const cuda_ffi_round_keys,
        counter_bits_le.as_ptr(),
        num_aes_inputs,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_aes_encrypt_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(output, &cuda_ffi_output);
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_unchecked_aes_ctr_256_encrypt<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    output: &mut CudaRadixCiphertext,
    iv: &CudaRadixCiphertext,
    round_keys: &CudaRadixCiphertext,
    start_counter: u128,
    num_aes_inputs: u32,
    sbox_parallelism: u32,
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
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let mut output_degrees = output.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut output_noise_levels = output.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let mut cuda_ffi_output =
        prepare_cuda_radix_ffi(output, &mut output_degrees, &mut output_noise_levels);

    let mut iv_degrees = iv.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut iv_noise_levels = iv.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_iv = prepare_cuda_radix_ffi(iv, &mut iv_degrees, &mut iv_noise_levels);

    let mut round_keys_degrees = round_keys.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut round_keys_noise_levels = round_keys
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let cuda_ffi_round_keys = prepare_cuda_radix_ffi(
        round_keys,
        &mut round_keys_degrees,
        &mut round_keys_noise_levels,
    );

    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let counter_bits_le: Vec<u64> = (0..num_aes_inputs)
        .flat_map(|i| {
            let current_counter = start_counter + i as u128;
            (0..128).map(move |bit_index| ((current_counter >> bit_index) & 1) as u64)
        })
        .collect();

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_aes_encrypt_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        noise_reduction_type as u32,
        num_aes_inputs,
        sbox_parallelism,
    );

    cuda_integer_aes_ctr_256_encrypt_64(
        streams.ffi(),
        &raw mut cuda_ffi_output,
        &raw const cuda_ffi_iv,
        &raw const cuda_ffi_round_keys,
        counter_bits_le.as_ptr(),
        num_aes_inputs,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_aes_encrypt_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(output, &cuda_ffi_output);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_aes_ctr_encrypt_size_on_gpu(
    streams: &CudaStreams,
    num_aes_inputs: u32,
    sbox_parallelism: u32,
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size = unsafe {
        scratch_cuda_integer_aes_encrypt_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            false,
            noise_reduction_type as u32,
            num_aes_inputs,
            sbox_parallelism,
        )
    };

    unsafe { cleanup_cuda_integer_aes_encrypt_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr)) };

    size
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_aes_key_expansion<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    expanded_keys: &mut CudaRadixCiphertext,
    key: &CudaRadixCiphertext,
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
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let mut expanded_keys_degrees = expanded_keys
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut expanded_keys_noise_levels = expanded_keys
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_expanded_keys = prepare_cuda_radix_ffi(
        expanded_keys,
        &mut expanded_keys_degrees,
        &mut expanded_keys_noise_levels,
    );

    let mut key_degrees = key.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut key_noise_levels = key.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_key = prepare_cuda_radix_ffi(key, &mut key_degrees, &mut key_noise_levels);

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_key_expansion_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_key_expansion_64(
        streams.ffi(),
        &raw mut cuda_ffi_expanded_keys,
        &raw const cuda_ffi_key,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_key_expansion_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(expanded_keys, &cuda_ffi_expanded_keys);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_aes_key_expansion_size_on_gpu(
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size = unsafe {
        scratch_cuda_integer_key_expansion_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            true,
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_integer_key_expansion_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr))
    };

    size
}

#[allow(clippy::too_many_arguments)]
/// # Safety
///
/// - The data must not be moved or dropped while being used by the CUDA kernel.
/// - This function assumes exclusive access to the passed data; violating this may lead to
///   undefined behavior.
pub(crate) unsafe fn cuda_backend_aes_key_expansion_256<T: UnsignedInteger, B: Numeric>(
    streams: &CudaStreams,
    expanded_keys: &mut CudaRadixCiphertext,
    key: &CudaRadixCiphertext,
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
    grouping_factor: LweBskGroupingFactor,
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) {
    let mut expanded_keys_degrees = expanded_keys
        .info
        .blocks
        .iter()
        .map(|b| b.degree.0)
        .collect();
    let mut expanded_keys_noise_levels = expanded_keys
        .info
        .blocks
        .iter()
        .map(|b| b.noise_level.0)
        .collect();
    let mut cuda_ffi_expanded_keys = prepare_cuda_radix_ffi(
        expanded_keys,
        &mut expanded_keys_degrees,
        &mut expanded_keys_noise_levels,
    );

    let mut key_degrees = key.info.blocks.iter().map(|b| b.degree.0).collect();
    let mut key_noise_levels = key.info.blocks.iter().map(|b| b.noise_level.0).collect();
    let cuda_ffi_key = prepare_cuda_radix_ffi(key, &mut key_degrees, &mut key_noise_levels);

    let noise_reduction_type = resolve_ms_noise_reduction_config(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    scratch_cuda_integer_key_expansion_256_64(
        streams.ffi(),
        std::ptr::addr_of_mut!(mem_ptr),
        glwe_dimension.0 as u32,
        polynomial_size.0 as u32,
        lwe_dimension.0 as u32,
        ks_level.0 as u32,
        ks_base_log.0 as u32,
        pbs_level.0 as u32,
        pbs_base_log.0 as u32,
        grouping_factor.0 as u32,
        message_modulus.0 as u32,
        carry_modulus.0 as u32,
        pbs_type as u32,
        true,
        noise_reduction_type as u32,
    );

    cuda_integer_key_expansion_256_64(
        streams.ffi(),
        &raw mut cuda_ffi_expanded_keys,
        &raw const cuda_ffi_key,
        mem_ptr,
        bootstrapping_key.ptr.as_ptr(),
        keyswitch_key.ptr.as_ptr(),
    );

    cleanup_cuda_integer_key_expansion_256_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr));

    update_noise_degree(expanded_keys, &cuda_ffi_expanded_keys);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cuda_backend_get_aes_key_expansion_256_size_on_gpu(
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
    pbs_type: PBSType,
    ms_noise_reduction_configuration: Option<&CudaModulusSwitchNoiseReductionConfiguration>,
) -> u64 {
    let noise_reduction_type = resolve_noise_reduction_type(ms_noise_reduction_configuration);

    let mut mem_ptr: *mut i8 = std::ptr::null_mut();
    let size = unsafe {
        scratch_cuda_integer_key_expansion_256_64(
            streams.ffi(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            grouping_factor.0 as u32,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            pbs_type as u32,
            true,
            noise_reduction_type as u32,
        )
    };

    unsafe {
        cleanup_cuda_integer_key_expansion_256_64(streams.ffi(), std::ptr::addr_of_mut!(mem_ptr))
    };

    size
}
