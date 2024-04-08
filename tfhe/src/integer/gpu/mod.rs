pub mod ciphertext;
pub mod server_key;

use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweDimension, PolynomialSize, UnsignedInteger,
};
use crate::integer::{ClientKey, RadixClientKey};
use crate::shortint::{CarryModulus, MessageModulus};
pub use server_key::CudaServerKey;
use std::cmp::min;
use tfhe_cuda_backend::cuda_bind::*;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum BitOpType {
    And = 0,
    Or = 1,
    Xor = 2,
    Not = 3,
    ScalarAnd = 4,
    ScalarOr = 5,
    ScalarXor = 6,
}

#[allow(dead_code)]
#[repr(u32)]
enum PBSType {
    MultiBit = 0,
    Classical = 1,
}

#[repr(u32)]
enum ShiftRotateType {
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

pub fn gen_keys_gpu<P>(parameters_set: P, stream: &CudaStream) -> (ClientKey, CudaServerKey)
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
        };

        crate::shortint::parameters::ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
            pbs_params,
            wopbs_params,
        ))
        .unwrap()
    } else {
        shortint_parameters_set
    };

    let gen_keys_inner = |parameters_set, stream: &CudaStream| {
        let cks = ClientKey::new(parameters_set);
        let sks = CudaServerKey::new(&cks, stream);

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
    gen_keys_inner(shortint_parameters_set, stream)
    // }
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys_gpu], this returns a [RadixClientKey]
///
/// ```rust
/// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
/// use tfhe::integer::gpu::gen_keys_radix_gpu;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// let gpu_index = 0;
/// let device = CudaDevice::new(gpu_index);
/// let mut stream = CudaStream::new_unchecked(device);
/// // generate the client key and the server key:
/// let num_blocks = 4;
/// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
/// ```
pub fn gen_keys_radix_gpu<P>(
    parameters_set: P,
    num_blocks: usize,
    stream: &CudaStream,
) -> (RadixClientKey, CudaServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let (cks, sks) = gen_keys_gpu(parameters_set, stream);

    (RadixClientKey::from((cks, num_blocks)), sks)
}

impl CudaStream {
    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn scalar_addition_integer_radix_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array: &mut CudaVec<T>,
        scalar_input: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
        message_modulus: u32,
        carry_modulus: u32,
    ) {
        cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
            self.as_c_ptr(),
            lwe_array.as_mut_c_ptr(),
            scalar_input.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
            message_modulus,
            carry_modulus,
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_mul_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        lwe_array: &mut CudaVec<T>,
        decomposed_scalar: &[T],
        has_at_least_one_set: &[T],
        bootstrapping_key: &CudaVec<f64>,
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
        num_blocks: u32,
        num_scalars: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_scalar_mul_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );

        cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
            self.as_c_ptr(),
            lwe_array.as_mut_c_ptr(),
            decomposed_scalar.as_ptr().cast::<u64>(),
            has_at_least_one_set.as_ptr().cast::<u64>(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            (glwe_dimension.0 * polynomial_size.0) as u32,
            polynomial_size.0 as u32,
            message_modulus.0 as u32,
            num_blocks,
            num_scalars,
        );

        cleanup_cuda_integer_radix_scalar_mul(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_mul_integer_radix_multibit_kb_async<T: UnsignedInteger>(
        &self,
        lwe_array: &mut CudaVec<T>,
        decomposed_scalar: &[T],
        has_at_least_one_set: &[T],
        bootstrapping_key: &CudaVec<u64>,
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
        grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        num_scalars: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_scalar_mul_kb_64(
            self.as_c_ptr(),
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
            PBSType::MultiBit as u32,
            true,
        );

        cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
            self.as_c_ptr(),
            lwe_array.as_mut_c_ptr(),
            decomposed_scalar.as_ptr().cast::<u64>(),
            has_at_least_one_set.as_ptr().cast::<u64>(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            (glwe_dimension.0 * polynomial_size.0) as u32,
            polynomial_size.0 as u32,
            message_modulus.0 as u32,
            num_blocks,
            num_scalars,
        );

        cleanup_cuda_integer_radix_scalar_mul(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_add_integer_radix_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_blocks: u32,
    ) {
        cuda_add_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_blocks,
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_mul_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_left: &CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            0,
            num_blocks,
            PBSType::Classical as u32,
            self.device().get_max_shared_memory() as u32,
            true,
        );
        cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            mem_ptr,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            0,
            num_blocks,
            PBSType::Classical as u32,
            self.device().get_max_shared_memory() as u32,
        );
        cleanup_cuda_integer_mult(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_mul_integer_radix_multibit_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_left: &CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        glwe_dimension: GlweDimension,
        lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
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
            PBSType::MultiBit as u32,
            self.device().get_max_shared_memory() as u32,
            true,
        );
        cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            mem_ptr,
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
            PBSType::MultiBit as u32,
            self.device().get_max_shared_memory() as u32,
        );
        cleanup_cuda_integer_mult(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_mul_integer_radix_classic_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            0,
            num_blocks,
            PBSType::Classical as u32,
            self.device().get_max_shared_memory() as u32,
            true,
        );
        cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            mem_ptr,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            glwe_dimension.0 as u32,
            lwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            0,
            num_blocks,
            PBSType::Classical as u32,
            self.device().get_max_shared_memory() as u32,
        );
        cleanup_cuda_integer_mult(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_mul_integer_radix_multibit_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        glwe_dimension: GlweDimension,
        lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        ks_level: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
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
            PBSType::MultiBit as u32,
            self.device().get_max_shared_memory() as u32,
            true,
        );
        cuda_integer_mult_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            mem_ptr,
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
            PBSType::MultiBit as u32,
            self.device().get_max_shared_memory() as u32,
        );
        cleanup_cuda_integer_mult(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_bitop_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_left: &CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        glwe_dimension: GlweDimension,
        big_lwe_dimension: LweDimension,
        small_lwe_dimension: LweDimension,
        polynomial_size: PolynomialSize,
        ks_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        pbs_base_log: DecompositionBaseLog,
        op: BitOpType,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            op as u32,
            true,
        );
        cuda_bitop_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_bitop_integer_radix_classic_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            op as u32,
            true,
        );
        cuda_bitop_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_bitnot_integer_radix_classic_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            BitOpType::Not as u32,
            true,
        );
        cuda_bitnot_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_bitnot_integer_radix_multibit_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            BitOpType::Not as u32,
            true,
        );
        cuda_bitnot_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_bitop_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe: &mut CudaVec<T>,
        clear_blocks: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        grouping_factor: LweBskGroupingFactor,
        op: BitOpType,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
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
            PBSType::MultiBit as u32,
            op as u32,
            true,
        );
        cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe.as_mut_c_ptr(),
            radix_lwe.as_mut_c_ptr(),
            clear_blocks.as_c_ptr(),
            min(clear_blocks.len() as u32, num_blocks),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
            op as u32,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_bitop_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe: &mut CudaVec<T>,
        clear_blocks: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            op as u32,
            true,
        );
        cuda_scalar_bitop_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe.as_mut_c_ptr(),
            radix_lwe.as_mut_c_ptr(),
            clear_blocks.as_c_ptr(),
            min(clear_blocks.len() as u32, num_blocks),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
            op as u32,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_bitop_integer_radix_multibit_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        op: BitOpType,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_bitop_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            op as u32,
            true,
        );
        cuda_bitop_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_bitop(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_comparison_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_left: &CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_comparison_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            op as u32,
            is_signed,
            true,
        );

        cuda_comparison_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );

        cleanup_cuda_integer_comparison(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_comparison_integer_radix_multibit_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_left: &CudaVec<T>,
        radix_lwe_right: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        op: ComparisonType,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_comparison_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            op as u32,
            is_signed,
            true,
        );
        cuda_comparison_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_left.as_c_ptr(),
            radix_lwe_right.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_comparison(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_comparison_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_in: &CudaVec<T>,
        scalar_blocks: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
        num_scalar_blocks: u32,
        op: ComparisonType,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_comparison_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            op as u32,
            is_signed,
            true,
        );

        cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_in.as_c_ptr(),
            scalar_blocks.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
            num_scalar_blocks,
        );

        cleanup_cuda_integer_comparison(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_comparison_integer_radix_multibit_kb_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_in: &CudaVec<T>,
        scalar_blocks: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        num_scalar_blocks: u32,
        op: ComparisonType,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_comparison_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            op as u32,
            is_signed,
            true,
        );
        cuda_scalar_comparison_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_in.as_c_ptr(),
            scalar_blocks.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
            num_scalar_blocks,
        );
        cleanup_cuda_integer_comparison(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn full_propagate_classic_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_input: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_full_propagation_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_level.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );
        cuda_full_propagation_64_inplace(
            self.as_c_ptr(),
            radix_lwe_input.as_mut_c_ptr(),
            mem_ptr,
            keyswitch_key.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            0,
            num_blocks,
        );
        cleanup_cuda_full_propagation(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn full_propagate_multibit_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_input: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        ks_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        pbs_base_log: DecompositionBaseLog,
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_full_propagation_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            pbs_level.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            true,
        );
        cuda_full_propagation_64_inplace(
            self.as_c_ptr(),
            radix_lwe_input.as_mut_c_ptr(),
            mem_ptr,
            keyswitch_key.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            ks_base_log.0 as u32,
            ks_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
        );
        cleanup_cuda_full_propagation(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn propagate_single_carry_classic_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_input: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
        scratch_cuda_propagate_single_carry_kb_64_inplace(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );
        cuda_propagate_single_carry_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_input.as_mut_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_propagate_single_carry(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn propagate_single_carry_multibit_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_input: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        ks_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        pbs_base_log: DecompositionBaseLog,
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        let big_lwe_dimension: u32 = glwe_dimension.0 as u32 * polynomial_size.0 as u32;
        scratch_cuda_propagate_single_carry_kb_64_inplace(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            true,
        );
        cuda_propagate_single_carry_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_input.as_mut_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_propagate_single_carry(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_shift_left_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::LeftShift as u32,
            true,
        );
        cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_logical_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_shift_left_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::LeftShift as u32,
            true,
        );
        cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_logical_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_logical_shift_right_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_logical_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_logical_shift_right_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_logical_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_arithmetic_shift_right_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_arithmetic_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_arithmetic_shift_right_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        shift: u32,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            shift,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_arithmetic_scalar_shift(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_shift_right_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::RightShift as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_shift_right_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::RightShift as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_shift_left_integer_radix_classic_kb_assign_async<T: UnsignedInteger>(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::LeftShift as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_shift_left_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::LeftShift as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_rotate_right_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::RightRotate as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_rotate_right_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::RightRotate as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_rotate_left_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::LeftRotate as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_rotate_left_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        radix_shift: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        is_signed: bool,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_shift_and_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::LeftRotate as u32,
            is_signed,
            true,
        );
        cuda_integer_radix_shift_and_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            radix_shift.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_shift_and_rotate(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_cmux_integer_radix_classic_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_condition: &CudaVec<T>,
        radix_lwe_true: &CudaVec<T>,
        radix_lwe_false: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_cmux_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );
        cuda_cmux_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_condition.as_c_ptr(),
            radix_lwe_true.as_c_ptr(),
            radix_lwe_false.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_cmux(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_cmux_integer_radix_multibit_kb_async<T: UnsignedInteger>(
        &self,
        radix_lwe_out: &mut CudaVec<T>,
        radix_lwe_condition: &CudaVec<T>,
        radix_lwe_true: &CudaVec<T>,
        radix_lwe_false: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_cmux_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            true,
        );
        cuda_cmux_integer_radix_ciphertext_kb_64(
            self.as_c_ptr(),
            radix_lwe_out.as_mut_c_ptr(),
            radix_lwe_condition.as_c_ptr(),
            radix_lwe_true.as_c_ptr(),
            radix_lwe_false.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_cmux(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_rotate_left_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        n: u32,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::LeftShift as u32,
            true,
        );
        cuda_integer_radix_scalar_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            n,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_scalar_rotate(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_rotate_left_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        n: u32,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::LeftShift as u32,
            true,
        );
        cuda_integer_radix_scalar_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            n,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_scalar_rotate(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_rotate_right_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        n: u32,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_scalar_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            n,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_scalar_rotate(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_scalar_rotate_right_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        radix_lwe_left: &mut CudaVec<T>,
        n: u32,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_scalar_rotate_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            ShiftRotateType::RightShift as u32,
            true,
        );
        cuda_integer_radix_scalar_rotate_kb_64_inplace(
            self.as_c_ptr(),
            radix_lwe_left.as_mut_c_ptr(),
            n,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_scalar_rotate(self.as_c_ptr(), std::ptr::addr_of_mut!(mem_ptr));
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_sum_ciphertexts_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        result: &mut CudaVec<T>,
        radix_list: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_sum_ciphertexts_vec_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            num_radixes,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );
        cuda_integer_radix_sum_ciphertexts_vec_kb_64(
            self.as_c_ptr(),
            result.as_mut_c_ptr(),
            radix_list.as_mut_c_ptr(),
            num_radixes,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_sum_ciphertexts_vec(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_sum_ciphertexts_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        result: &mut CudaVec<T>,
        radix_list: &mut CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        lwe_dimension: LweDimension,
        ks_level: DecompositionLevelCount,
        ks_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        pbs_base_log: DecompositionBaseLog,
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
        num_radixes: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_sum_ciphertexts_vec_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            num_radixes,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            true,
        );
        cuda_integer_radix_sum_ciphertexts_vec_kb_64(
            self.as_c_ptr(),
            result.as_mut_c_ptr(),
            radix_list.as_mut_c_ptr(),
            num_radixes,
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_sum_ciphertexts_vec(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_unsigned_overflowing_sub_integer_radix_classic_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        ct_res: &mut CudaVec<T>,
        ct_overflowed: &mut CudaVec<T>,
        lhs: &CudaVec<T>,
        rhs: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        keyswitch_key: &CudaVec<u64>,
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
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_overflowing_sub_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            0,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::Classical as u32,
            true,
        );
        cuda_integer_radix_overflowing_sub_kb_64(
            self.as_c_ptr(),
            ct_res.as_mut_c_ptr(),
            ct_overflowed.as_mut_c_ptr(),
            lhs.as_c_ptr(),
            rhs.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_overflowing_sub(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// # Safety
    ///
    /// - [CudaStream::synchronize] __must__ be called after this function
    /// as soon as synchronization is required
    pub unsafe fn unchecked_unsigned_overflowing_sub_integer_radix_multibit_kb_assign_async<
        T: UnsignedInteger,
    >(
        &self,
        ct_res: &mut CudaVec<T>,
        ct_overflowed: &mut CudaVec<T>,
        lhs: &CudaVec<T>,
        rhs: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        keyswitch_key: &CudaVec<u64>,
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
        pbs_grouping_factor: LweBskGroupingFactor,
        num_blocks: u32,
    ) {
        let mut mem_ptr: *mut i8 = std::ptr::null_mut();
        scratch_cuda_integer_radix_overflowing_sub_kb_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            big_lwe_dimension.0 as u32,
            small_lwe_dimension.0 as u32,
            ks_level.0 as u32,
            ks_base_log.0 as u32,
            pbs_level.0 as u32,
            pbs_base_log.0 as u32,
            pbs_grouping_factor.0 as u32,
            num_blocks,
            message_modulus.0 as u32,
            carry_modulus.0 as u32,
            PBSType::MultiBit as u32,
            true,
        );
        cuda_integer_radix_overflowing_sub_kb_64(
            self.as_c_ptr(),
            ct_res.as_mut_c_ptr(),
            ct_overflowed.as_mut_c_ptr(),
            lhs.as_c_ptr(),
            rhs.as_c_ptr(),
            mem_ptr,
            bootstrapping_key.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            num_blocks,
        );
        cleanup_cuda_integer_radix_overflowing_sub(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(mem_ptr),
        );
    }
}
