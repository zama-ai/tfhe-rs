use crate::core_crypto::entities::{Cleartext, GlweCiphertext, LweCiphertextList};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{CudaLweList, CudaStreams};
use crate::core_crypto::prelude::{
    ContiguousEntityContainerMut, LweBskGroupingFactor, LweCiphertextCount,
};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    add_and_propagate_single_carry_assign_async, apply_bivariate_lut_kb_async,
    apply_many_univariate_lut_kb_async, apply_univariate_lut_kb_async,
    compute_prefix_sum_hillis_steele_async, extend_radix_with_trivial_zero_blocks_msb_async,
    full_propagate_assign_async, propagate_single_carry_assign_async, trim_radix_blocks_lsb_async,
    CudaServerKey, PBSType,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::engine::{fill_accumulator_no_encoding, fill_many_lut_accumulator};
use crate::shortint::parameters::AtomicPatternKind;
use crate::shortint::server_key::{
    generate_lookup_table, BivariateLookupTableOwned, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned,
};
use crate::shortint::{PBSOrder, PaddingBit, ShortintEncoding};

mod abs;
mod add;
mod bitwise_op;
mod cmux;
mod comparison;
mod div_mod;
mod even_odd;
mod ilog2;
mod mul;
mod neg;
mod oprf;
mod rotate;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_comparison;
mod scalar_div_mod;
mod scalar_mul;
mod scalar_rotate;
mod scalar_shift;
mod scalar_sub;
mod shift;
mod sub;
mod vector_comparisons;
mod vector_find;

#[cfg(test)]
mod tests_long_run;
#[cfg(test)]
mod tests_signed;
#[cfg(test)]
mod tests_unsigned;

impl CudaServerKey {
    /// Create a trivial ciphertext filled with zeros on the GPU.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ctxt: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_zero_radix(num_blocks, &streams);
    /// let ctxt = d_ctxt.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(0, dec);
    /// ```
    pub fn create_trivial_zero_radix<T: CudaIntegerRadixCiphertext>(
        &self,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let res = unsafe { self.create_trivial_zero_radix_async(num_blocks, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn create_trivial_zero_radix_async<T: CudaIntegerRadixCiphertext>(
        &self,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        self.create_trivial_radix_async(0, num_blocks, streams)
    }

    /// Create a trivial ciphertext on the GPU
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ctxt: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(212u64, num_blocks, &streams);
    /// let ctxt = d_ctxt.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(212, dec);
    /// ```
    pub fn create_trivial_radix<Scalar, T>(
        &self,
        scalar: Scalar,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let res = unsafe { self.create_trivial_radix_async(scalar, num_blocks, streams) };
        streams.synchronize();
        res
    }

    pub(crate) fn encoding(&self) -> ShortintEncoding<u64> {
        ShortintEncoding {
            ciphertext_modulus: self.ciphertext_modulus,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            padding_bit: PaddingBit::Yes,
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn create_trivial_radix_async<Scalar, T>(
        &self,
        scalar: Scalar,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let lwe_size = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_size(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_size(),
        };

        let decomposer =
            BlockDecomposer::with_block_count(scalar, self.message_modulus.0.ilog2(), num_blocks)
                .iter_as::<u64>();
        let mut cpu_lwe_list = LweCiphertextList::new(
            0,
            lwe_size,
            LweCiphertextCount(num_blocks),
            self.ciphertext_modulus,
        );
        let mut info = Vec::with_capacity(num_blocks);
        for (block_value, mut lwe) in decomposer.zip(cpu_lwe_list.iter_mut()) {
            *lwe.get_mut_body().data = self.encoding().encode(Cleartext(block_value)).0;
            info.push(CudaBlockInfo {
                degree: Degree::new(block_value),
                message_modulus: self.message_modulus,
                carry_modulus: self.carry_modulus,
                atomic_pattern: AtomicPatternKind::Standard(self.pbs_order),
                noise_level: NoiseLevel::ZERO,
            });
        }

        let d_blocks =
            CudaLweCiphertextList::from_lwe_ciphertext_list_async(&cpu_lwe_list, streams);

        T::from(CudaRadixCiphertext {
            d_blocks,
            info: CudaRadixCiphertextInfo { blocks: info },
        })
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub(crate) unsafe fn propagate_single_carry_assign_async<T>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
        input_carry: Option<&CudaBooleanBlock>,
        requested_flag: OutputFlag,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut carry_out: T = self.create_trivial_zero_radix(1, streams);
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        let uses_carry = input_carry.map_or(0u32, |_block| 1u32);
        let aux_block: T = self.create_trivial_zero_radix(1, streams);
        let in_carry: &CudaRadixCiphertext =
            input_carry.map_or_else(|| aux_block.as_ref(), |block| block.0.as_ref());

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                propagate_single_carry_assign_async(
                    streams,
                    ciphertext,
                    carry_out.as_mut(),
                    in_carry,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    requested_flag,
                    uses_carry,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                propagate_single_carry_assign_async(
                    streams,
                    ciphertext,
                    carry_out.as_mut(),
                    in_carry,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    num_blocks,
                    ciphertext.info.blocks.first().unwrap().message_modulus,
                    ciphertext.info.blocks.first().unwrap().carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    requested_flag,
                    uses_carry,
                    None,
                );
            }
        }
        carry_out
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub(crate) unsafe fn add_and_propagate_single_carry_assign_async<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
        streams: &CudaStreams,
        input_carry: Option<&CudaBooleanBlock>,
        requested_flag: OutputFlag,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut carry_out: T = self.create_trivial_zero_radix(1, streams);

        let num_blocks = lhs.as_mut().d_blocks.lwe_ciphertext_count().0 as u32;
        let uses_carry = input_carry.map_or(0u32, |_block| 1u32);
        let aux_block: T = self.create_trivial_zero_radix(1, streams);
        let in_carry: &CudaRadixCiphertext =
            input_carry.map_or_else(|| aux_block.as_ref(), |block| block.0.as_ref());

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                add_and_propagate_single_carry_assign_async(
                    streams,
                    lhs.as_mut(),
                    rhs.as_ref(),
                    carry_out.as_mut(),
                    in_carry,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    num_blocks,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    requested_flag,
                    uses_carry,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                add_and_propagate_single_carry_assign_async(
                    streams,
                    lhs.as_mut(),
                    rhs.as_ref(),
                    carry_out.as_mut(),
                    in_carry,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    num_blocks,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    requested_flag,
                    uses_carry,
                    None,
                );
            }
        }
        carry_out
    }

    pub(crate) unsafe fn full_propagate_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) {
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0 as u32;
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    full_propagate_assign_async(
                        streams,
                        ciphertext,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.input_lwe_dimension(),
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        num_blocks,
                        ciphertext.info.blocks.first().unwrap().message_modulus,
                        ciphertext.info.blocks.first().unwrap().carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    full_propagate_assign_async(
                        streams,
                        ciphertext,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        num_blocks,
                        ciphertext.info.blocks.first().unwrap().message_modulus,
                        ciphertext.info.blocks.first().unwrap().carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    /// Prepend trivial zero LSB blocks to an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::{CudaRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(7u64, num_blocks, &streams);
    /// let ct1 = d_ct1.to_radix_ciphertext(&streams);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let added_blocks = 2;
    /// let d_ct_res =
    ///     sks.extend_radix_with_trivial_zero_blocks_lsb(&d_ct1, added_blocks, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(
    ///     7 * (PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.message_modulus.0).pow(added_blocks as u32),
    ///     res
    /// );
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_lsb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let res = unsafe {
            self.extend_radix_with_trivial_zero_blocks_lsb_async(ct, num_blocks, streams)
        };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn extend_radix_with_trivial_zero_blocks_lsb_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        if num_blocks == 0 {
            return ct.duplicate_async(streams);
        }
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = num_blocks * lwe_size.0;

        let mut extended_ct_vec = CudaVec::new_async(new_num_blocks * lwe_size.0, streams, 0);
        extended_ct_vec.memset_async(0u64, streams, 0);
        extended_ct_vec.copy_self_range_gpu_to_gpu_async(
            shift..,
            &ct.as_ref().d_blocks.0.d_vec,
            streams,
            0,
        );
        let extended_ct_list = CudaLweCiphertextList::from_cuda_vec(
            extended_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );

        let extended_ct_info = ct
            .as_ref()
            .info
            .after_extend_radix_with_trivial_zero_blocks_lsb(num_blocks);
        T::from(CudaRadixCiphertext::new(extended_ct_list, extended_ct_info))
    }

    /// Append trivial zero MSB blocks to an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(7u64, num_blocks, &streams);
    /// let ct1 = d_ct1.to_radix_ciphertext(&streams);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.extend_radix_with_trivial_zero_blocks_msb(&d_ct1, 2, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 6);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn extend_radix_with_trivial_zero_blocks_msb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let res = unsafe {
            self.extend_radix_with_trivial_zero_blocks_msb_async(ct, num_blocks, streams)
        };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn extend_radix_with_trivial_zero_blocks_msb_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let mut output: T = unsafe {
            self.create_trivial_zero_radix_async(
                ct.as_ref().d_blocks.lwe_ciphertext_count().0 + num_blocks,
                streams,
            )
        };

        unsafe {
            extend_radix_with_trivial_zero_blocks_msb_async(output.as_mut(), ct.as_ref(), streams);
        }
        output
    }

    /// Remove LSB blocks from an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(119u64, num_blocks, &streams);
    /// let ct1 = d_ct1.to_radix_ciphertext(&streams);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.trim_radix_blocks_lsb(&d_ct1, 2, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_lsb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let res = unsafe { self.trim_radix_blocks_lsb_async(ct, num_blocks, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn trim_radix_blocks_lsb_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let output_num_blocks = ct
            .as_ref()
            .d_blocks
            .lwe_ciphertext_count()
            .0
            .checked_sub(num_blocks)
            .expect("Invalid number of blocks to trim (shouldn't be <= 0)");

        let mut output: T =
            unsafe { self.create_trivial_zero_radix_async(output_num_blocks, streams) };

        unsafe {
            trim_radix_blocks_lsb_async(output.as_mut(), ct.as_ref(), streams);
        }

        output
    }

    /// Remove MSB blocks from an existing [`CudaUnsignedRadixCiphertext`] or
    /// [`CudaSignedRadixCiphertext`](`crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext`)
    /// and returns the result as a new ciphertext on GPU. This can be useful for casting
    /// operations.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let d_ct1: CudaUnsignedRadixCiphertext =
    ///     sks.create_trivial_radix(119u64, num_blocks, &streams);
    /// let ct1 = d_ct1.to_radix_ciphertext(&streams);
    /// assert_eq!(ct1.blocks().len(), 4);
    ///
    /// let d_ct_res = sks.trim_radix_blocks_msb(&d_ct1, 2, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 2);
    ///
    /// // Decrypt
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(7, res);
    /// ```
    pub fn trim_radix_blocks_msb<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        let res = unsafe { self.trim_radix_blocks_msb_async(ct, num_blocks, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn trim_radix_blocks_msb_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        if num_blocks == 0 {
            return ct.duplicate_async(streams);
        }
        let new_num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 - num_blocks;
        let ciphertext_modulus = ct.as_ref().d_blocks.ciphertext_modulus();
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size();
        let shift = new_num_blocks * lwe_size.0;

        let mut trimmed_ct_vec = CudaVec::new_async(new_num_blocks * lwe_size.0, streams, 0);
        trimmed_ct_vec.copy_src_range_gpu_to_gpu_async(
            0..shift,
            &ct.as_ref().d_blocks.0.d_vec,
            streams,
            0,
        );
        let trimmed_ct_list = CudaLweCiphertextList::from_cuda_vec(
            trimmed_ct_vec,
            LweCiphertextCount(new_num_blocks),
            ciphertext_modulus,
        );
        let trimmed_ct_info = ct.as_ref().info.after_trim_radix_blocks_msb(new_num_blocks);
        T::from(CudaRadixCiphertext::new(trimmed_ct_list, trimmed_ct_info))
    }

    pub(crate) fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let (glwe_size, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
        };

        let size = LookupTableSize::new(glwe_size, polynomial_size);

        generate_lookup_table(
            size,
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            f,
        )
    }
    pub(crate) fn generate_lookup_table_no_encode<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let (glwe_size, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
        };
        let mut acc = GlweCiphertext::new(0, glwe_size, polynomial_size, self.ciphertext_modulus);

        fill_accumulator_no_encoding(&mut acc, polynomial_size, glwe_size, f);

        LookupTableOwned {
            acc,
            // We should not rely on the degree in this case
            // The degree should be set manually on the outputs of PBS by this LUT
            degree: Degree::new(self.message_modulus.0 * self.carry_modulus.0 * 2),
        }
    }

    pub fn generate_many_lookup_table(
        &self,
        functions: &[&dyn Fn(u64) -> u64],
    ) -> ManyLookupTableOwned {
        let (glwe_size, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.glwe_dimension.to_glwe_size(), d_bsk.polynomial_size)
            }
        };
        let mut acc = GlweCiphertext::new(0, glwe_size, polynomial_size, self.ciphertext_modulus);

        let (input_max_degree, sample_extraction_stride, per_function_output_degree) =
            fill_many_lut_accumulator(
                &mut acc,
                polynomial_size,
                glwe_size,
                self.message_modulus,
                self.carry_modulus,
                functions,
            );

        ManyLookupTableOwned {
            acc,
            input_max_degree,
            sample_extraction_stride,
            per_function_output_degree,
        }
    }

    /// Generates a bivariate accumulator
    pub(crate) fn generate_lookup_table_bivariate<F>(&self, f: F) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        // Depending on the factor used, rhs and / or lhs may have carries
        // (degree >= message_modulus) which is why we need to apply the message_modulus
        // to clear them
        let message_modulus = self.message_modulus.0;
        let factor_u64 = message_modulus;
        let wrapped_f = |input: u64| -> u64 {
            let lhs = (input / factor_u64) % message_modulus;
            let rhs = (input % factor_u64) % message_modulus;

            f(lhs, rhs)
        };
        let accumulator = self.generate_lookup_table(wrapped_f);

        BivariateLookupTableOwned {
            acc: accumulator,
            ct_right_modulus: self.message_modulus,
        }
    }

    /// Applies the lookup table on the range of ciphertexts
    ///
    /// The output must have exactly block_range.len() blocks
    ///
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn apply_lookup_table_async(
        &self,
        output: &mut CudaRadixCiphertext,
        input: &CudaRadixCiphertext,
        lut: &LookupTableOwned,
        block_range: std::ops::Range<usize>,
        streams: &CudaStreams,
    ) {
        if block_range.is_empty() {
            return;
        }

        assert_eq!(
            input.d_blocks.lwe_dimension(),
            output.d_blocks.lwe_dimension()
        );

        let lwe_dimension = input.d_blocks.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size().0;
        let num_output_blocks = output.d_blocks.lwe_ciphertext_count().0;

        let input_slice = input
            .d_blocks
            .0
            .d_vec
            .as_slice(lwe_size * block_range.start..lwe_size * block_range.end, 0)
            .unwrap();
        let mut output_slice = output.d_blocks.0.d_vec.as_mut_slice(.., 0).unwrap();
        let mut output_degrees = vec![0_u64; num_output_blocks];
        let mut output_noise_levels = vec![0_u64; num_output_blocks];

        let num_ct_blocks = block_range.len() as u32;
        let ct_modulus = input.d_blocks.ciphertext_modulus().raw_modulus_float();
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    apply_univariate_lut_kb_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &input_slice,
                        lut.acc.as_ref(),
                        lut.degree.0,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        num_ct_blocks,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                        ct_modulus,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    apply_univariate_lut_kb_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &input_slice,
                        lut.acc.as_ref(),
                        lut.degree.0,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        num_ct_blocks,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                        ct_modulus,
                    );
                }
            }
        }

        for (i, info) in output.info.blocks[block_range].iter_mut().enumerate() {
            info.degree = Degree(output_degrees[i]);
            info.noise_level = NoiseLevel(output_noise_levels[i]);
        }
    }

    /// Applies the bivariate lookup table on the range of ciphertexts
    ///
    /// The output must have exactly block_range.len() blocks
    ///
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn apply_bivariate_lookup_table_async(
        &self,
        output: &mut CudaRadixCiphertext,
        input_1: &CudaRadixCiphertext,
        input_2: &CudaRadixCiphertext,
        lut: &BivariateLookupTableOwned,
        block_range: std::ops::Range<usize>,
        streams: &CudaStreams,
    ) {
        if block_range.is_empty() {
            return;
        }

        assert_eq!(
            input_1.d_blocks.lwe_dimension(),
            output.d_blocks.lwe_dimension()
        );
        assert_eq!(
            input_2.d_blocks.lwe_dimension(),
            output.d_blocks.lwe_dimension()
        );

        let lwe_dimension = input_1.d_blocks.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size().0;
        let num_output_blocks = output.d_blocks.lwe_ciphertext_count().0;

        let input_slice_1 = input_1
            .d_blocks
            .0
            .d_vec
            .as_slice(lwe_size * block_range.start..lwe_size * block_range.end, 0)
            .unwrap();
        let input_slice_2 = input_2
            .d_blocks
            .0
            .d_vec
            .as_slice(lwe_size * block_range.start..lwe_size * block_range.end, 0)
            .unwrap();
        let mut output_slice = output.d_blocks.0.d_vec.as_mut_slice(.., 0).unwrap();
        let mut output_degrees = vec![0_u64; num_output_blocks];
        let mut output_noise_levels = vec![0_u64; num_output_blocks];

        let num_ct_blocks = block_range.len() as u32;
        let ct_modulus = input_1.d_blocks.ciphertext_modulus().raw_modulus_float();
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    apply_bivariate_lut_kb_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &input_slice_1,
                        &input_slice_2,
                        lut.acc.acc.as_ref(),
                        lut.acc.degree.0,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        num_ct_blocks,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        self.message_modulus.0 as u32,
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                        ct_modulus,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    apply_bivariate_lut_kb_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &input_slice_1,
                        &input_slice_2,
                        lut.acc.acc.as_ref(),
                        lut.acc.degree.0,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        num_ct_blocks,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        self.message_modulus.0 as u32,
                        None,
                        ct_modulus,
                    );
                }
            }
        }

        for (i, info) in output.info.blocks[block_range].iter_mut().enumerate() {
            info.degree = Degree(output_degrees[i]);
            info.noise_level = NoiseLevel(output_noise_levels[i]);
        }
    }
    /// Applies many lookup tables on the range of ciphertexts
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    /// };
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) =
    ///         gen_keys(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(
    ///         PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///         &streams,
    ///     );
    ///     let num_blocks = 2;
    ///     let msg = 3;
    ///     let ct = cks.encrypt_radix(msg, num_blocks);
    ///     let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 4;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 4;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = unsafe { sks.apply_many_lookup_table_async(d_ct.as_ref(), &luts, &streams) };
    ///     streams.synchronize();
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (d_res, function) in vec_res.iter().zip(functions) {
    ///         let d_res_unsigned = CudaUnsignedRadixCiphertext {
    ///             ciphertext: d_res.duplicate(&streams),
    ///         };
    ///         let res = d_res_unsigned.to_radix_ciphertext(&streams);
    ///         let dec: u64 = cks.decrypt_radix(&res);
    ///         println!(" compare {} vs {}", dec, function(msg));
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, &streams);
    ///     let num_blocks = 2;
    ///     let msg = 3;
    ///     let ct = cks.encrypt_radix(msg, num_blocks);
    ///     let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 8;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 8;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = unsafe { sks.apply_many_lookup_table_async(d_ct.as_ref(), &luts, &streams) };
    ///     streams.synchronize();
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (d_res, function) in vec_res.iter().zip(functions) {
    ///         let d_res_unsigned = CudaUnsignedRadixCiphertext {
    ///             ciphertext: d_res.duplicate(&streams),
    ///         };
    ///         let res = d_res_unsigned.to_radix_ciphertext(&streams);
    ///         let dec: u64 = cks.decrypt_radix(&res);
    ///         println!(" compare {} vs {}", dec, function(msg));
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// ```
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn apply_many_lookup_table_async(
        &self,
        input: &CudaRadixCiphertext,
        lut: &ManyLookupTableOwned,
        streams: &CudaStreams,
    ) -> Vec<CudaRadixCiphertext> {
        let lwe_dimension = input.d_blocks.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size().0;

        let input_slice = input.d_blocks.0.d_vec.as_slice(.., 0).unwrap();

        // The accumulator has been rotated, we can now proceed with the various sample extractions
        let function_count = lut.function_count();
        let num_ct_blocks = input.d_blocks.lwe_ciphertext_count().0;
        let total_radixes_size = num_ct_blocks * lwe_size * function_count;
        let mut output_radixes = CudaVec::new(total_radixes_size, streams, 0);

        let mut output_slice = output_radixes
            .as_mut_slice(0..total_radixes_size, 0)
            .unwrap();
        let mut output_degrees = vec![0_u64; num_ct_blocks * function_count];
        let mut output_noise_levels = vec![0_u64; num_ct_blocks * function_count];
        let ct_modulus = input.d_blocks.ciphertext_modulus().raw_modulus_float();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                apply_many_univariate_lut_kb_async(
                    streams,
                    &mut output_slice,
                    &mut output_degrees,
                    &mut output_noise_levels,
                    &input_slice,
                    lut.acc.as_ref(),
                    lut.input_max_degree.0,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    num_ct_blocks as u32,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    function_count as u32,
                    lut.sample_extraction_stride as u32,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                    ct_modulus,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                apply_many_univariate_lut_kb_async(
                    streams,
                    &mut output_slice,
                    &mut output_degrees,
                    &mut output_noise_levels,
                    &input_slice,
                    lut.acc.as_ref(),
                    lut.input_max_degree.0,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    num_ct_blocks as u32,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    function_count as u32,
                    lut.sample_extraction_stride as u32,
                    None,
                    ct_modulus,
                );
            }
        }

        let mut ciphertexts = Vec::<CudaRadixCiphertext>::with_capacity(function_count);

        for i in 0..function_count {
            let slice_size = num_ct_blocks * lwe_size;
            let mut ct = input.duplicate(streams);
            let mut ct_slice = ct.d_blocks.0.d_vec.as_mut_slice(0..slice_size, 0).unwrap();

            let slice_size = num_ct_blocks * lwe_size;
            let output_slice = output_radixes
                .as_mut_slice(slice_size * i..slice_size * (i + 1), 0)
                .unwrap();

            ct_slice.copy_from_gpu_async(&output_slice, streams, 0);

            for info in ct.info.blocks.iter_mut() {
                info.degree = lut.per_function_output_degree[i];
                info.noise_level = NoiseLevel::NOMINAL;
            }

            ciphertexts.push(ct);
        }

        ciphertexts
    }

    /// Applies the lookup table on the range of ciphertexts
    ///
    /// The output must have exactly block_range.len() blocks
    ///
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub(crate) unsafe fn compute_prefix_sum_hillis_steele_async(
        &self,
        output: &mut CudaRadixCiphertext,
        generates_or_propagates: &mut CudaRadixCiphertext,
        lut: &BivariateLookupTableOwned,
        block_range: std::ops::Range<usize>,
        streams: &CudaStreams,
    ) {
        if block_range.is_empty() {
            return;
        }
        assert_eq!(
            generates_or_propagates.d_blocks.lwe_dimension(),
            output.d_blocks.lwe_dimension()
        );

        let lwe_dimension = generates_or_propagates.d_blocks.lwe_dimension();
        let lwe_size = lwe_dimension.to_lwe_size().0;
        let num_blocks = block_range.len();

        let mut generates_or_propagates_slice = generates_or_propagates
            .d_blocks
            .0
            .d_vec
            .as_mut_slice(lwe_size * block_range.start..lwe_size * block_range.end, 0)
            .unwrap();
        let mut generates_or_propagates_degrees = vec![0; num_blocks];
        let mut generates_or_propagates_noise_levels = vec![0; num_blocks];
        for (i, block_index) in (block_range.clone()).enumerate() {
            generates_or_propagates_degrees[i] =
                generates_or_propagates.info.blocks[block_index].degree.0;
            generates_or_propagates_noise_levels[i] = generates_or_propagates.info.blocks
                [block_index]
                .noise_level
                .0;
        }
        let ct_modulus = output.d_blocks.ciphertext_modulus().raw_modulus_float();
        let mut output_slice = output
            .d_blocks
            .0
            .d_vec
            .as_mut_slice(lwe_size * block_range.start..lwe_size * block_range.end, 0)
            .unwrap();
        let mut output_degrees = vec![0_u64; num_blocks];
        let mut output_noise_levels = vec![0_u64; num_blocks];
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    compute_prefix_sum_hillis_steele_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &mut generates_or_propagates_slice,
                        &mut generates_or_propagates_degrees,
                        &mut generates_or_propagates_noise_levels,
                        lut.acc.acc.as_ref(),
                        lut.acc.degree.0,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        num_blocks as u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                        ct_modulus,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    compute_prefix_sum_hillis_steele_async(
                        streams,
                        &mut output_slice,
                        &mut output_degrees,
                        &mut output_noise_levels,
                        &mut generates_or_propagates_slice,
                        &mut generates_or_propagates_degrees,
                        &mut generates_or_propagates_noise_levels,
                        lut.acc.acc.as_ref(),
                        lut.acc.degree.0,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        num_blocks as u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                        ct_modulus,
                    );
                }
            }
        }

        for (i, info) in output.info.blocks[block_range.start..block_range.end]
            .iter_mut()
            .enumerate()
        {
            info.degree = Degree(output_degrees[i]);
            info.noise_level = NoiseLevel(output_noise_levels[i]);
        }
        for (i, info) in generates_or_propagates.info.blocks[block_range.start..block_range.end]
            .iter_mut()
            .enumerate()
        {
            info.degree = Degree(generates_or_propagates_degrees[i]);
            info.noise_level = NoiseLevel(generates_or_propagates_noise_levels[i]);
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub(crate) unsafe fn extend_radix_with_sign_msb_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> T {
        if num_blocks == 0 {
            return ct.duplicate_async(streams);
        }
        let message_modulus = self.message_modulus.0;
        let num_bits_in_block = message_modulus.ilog2();
        let padding_block_creator_lut = self.generate_lookup_table(|x| {
            let x = x % message_modulus;
            let x_sign_bit = (x >> (num_bits_in_block - 1)) & 1;
            // padding is a message full of 1 if sign bit is one
            // else padding is a zero message
            (message_modulus - 1) * x_sign_bit
        });
        let num_ct_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;
        let new_num_ct_blocks = num_ct_blocks + num_blocks;

        assert_ne!(num_ct_blocks, 0, "Cannot sign extend an empty ciphertext");
        let lwe_size = ct.as_ref().d_blocks.0.lwe_dimension.to_lwe_size().0;

        // Allocate the necessary amount of memory
        let mut output_radix = CudaVec::new(new_num_ct_blocks * lwe_size, streams, 0);
        output_radix.copy_from_gpu_async(&ct.as_ref().d_blocks.0.d_vec, streams, 0);
        // Get the last ct block
        let last_block = ct
            .as_ref()
            .d_blocks
            .0
            .d_vec
            .as_slice(lwe_size * (num_ct_blocks - 1).., 0)
            .unwrap();
        let mut output_slice = output_radix
            .as_mut_slice(lwe_size * num_ct_blocks..lwe_size * new_num_ct_blocks, 0)
            .unwrap();
        let (padding_block, new_blocks) = output_slice.split_at_mut(lwe_size, 0);
        let mut padding_block = padding_block.unwrap();
        let mut padding_block_degree = vec![0_u64; 1];
        let mut padding_block_noise_level = vec![0_u64; 1];
        let mut new_blocks = new_blocks.unwrap();
        let ct_modulus = ct
            .to_owned()
            .as_ref()
            .d_blocks
            .ciphertext_modulus()
            .raw_modulus_float();
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                apply_univariate_lut_kb_async(
                    streams,
                    &mut padding_block,
                    &mut padding_block_degree,
                    &mut padding_block_noise_level,
                    &last_block,
                    padding_block_creator_lut.acc.as_ref(),
                    padding_block_creator_lut.degree.0,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    1u32,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                    ct_modulus,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                apply_univariate_lut_kb_async(
                    streams,
                    &mut padding_block,
                    &mut padding_block_degree,
                    &mut padding_block_noise_level,
                    &last_block,
                    padding_block_creator_lut.acc.as_ref(),
                    padding_block_creator_lut.degree.0,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    1u32,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                    ct_modulus,
                );
            }
        }
        for i in 0..num_blocks - 1 {
            let mut output_block = new_blocks
                .get_mut(lwe_size * i..lwe_size * (i + 1), 0)
                .unwrap();
            output_block.copy_from_gpu_async(&padding_block, streams, 0);
        }
        let output_lwe_list = CudaLweCiphertextList(CudaLweList {
            d_vec: output_radix,
            lwe_ciphertext_count: LweCiphertextCount(new_num_ct_blocks),
            lwe_dimension: ct.as_ref().d_blocks.0.lwe_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        });
        let mut info = ct.as_ref().info.clone();
        let mut last_block_info = *ct.as_ref().info.blocks.last().unwrap();
        last_block_info.degree = Degree(padding_block_degree[0]);
        last_block_info.noise_level = NoiseLevel(padding_block_noise_level[0]);
        for _ in num_ct_blocks..new_num_ct_blocks {
            info.blocks.push(last_block_info);
        }

        T::from(CudaRadixCiphertext::new(output_lwe_list, info))
    }
    /// Cast a [`CudaUnsignedRadixCiphertext`] or a [`CudaSignedRadixCiphertext`]
    /// to a [`CudaUnsignedRadixCiphertext`] with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::IntegerCiphertext;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 4;
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg = -2i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    /// assert_eq!(ct1.blocks().len(), 4);
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.cast_to_unsigned(d_ct1, 8, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 8);
    ///
    /// // Decrypt
    /// let res: u16 = cks.decrypt(&ct_res);
    /// assert_eq!(msg as u16, res);
    /// ```
    pub fn cast_to_unsigned<T>(
        &self,
        source: T,
        target_num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.cast_to_unsigned_async(source, target_num_blocks, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn cast_to_unsigned_async<T>(
        &self,
        mut source: T,
        target_num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if !source.block_carries_are_empty() {
            self.full_propagate_assign_async(&mut source, streams);
        }
        let current_num_blocks = source.as_ref().info.blocks.len();
        if T::IS_SIGNED {
            // Casting from signed to unsigned
            // We have to trim or sign extend first
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let signed_res: T =
                    self.extend_radix_with_sign_msb_async(&source, num_blocks_to_add, streams);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let signed_res =
                    self.trim_radix_blocks_msb_async(&source, num_blocks_to_remove, streams);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            }
        } else {
            // Casting from unsigned to unsigned, this is just about trimming/extending with zeros
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let unsigned_res = self.extend_radix_with_trivial_zero_blocks_msb_async(
                    &source,
                    num_blocks_to_add,
                    streams,
                );
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let unsigned_res =
                    self.trim_radix_blocks_msb_async(&source, num_blocks_to_remove, streams);
                <CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            }
        }
    }

    /// Cast a `CudaUnsignedRadixCiphertext` or `CudaSignedRadixCiphertext` to a
    /// `CudaSignedRadixCiphertext` with a possibly different number of blocks
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, IntegerCiphertext};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let num_blocks = 8;
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg = u16::MAX;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// assert_eq!(ct1.blocks().len(), num_blocks);
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.cast_to_signed(d_ct1, 4, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    /// assert_eq!(ct_res.blocks().len(), 4);
    ///
    /// // Decrypt
    /// let res: i8 = cks.decrypt_signed(&ct_res);
    /// assert_eq!(msg as i8, res);
    /// ```
    pub fn cast_to_signed<T>(
        &self,
        source: T,
        target_num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        let res = unsafe { self.cast_to_signed_async(source, target_num_blocks, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronized
    pub unsafe fn cast_to_signed_async<T>(
        &self,
        mut source: T,
        target_num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        if !source.block_carries_are_empty() {
            self.full_propagate_assign_async(&mut source, streams);
        }

        let current_num_blocks = source.as_ref().info.blocks.len();

        if T::IS_SIGNED {
            // Casting from signed to signed
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let unsigned_res: T =
                    self.extend_radix_with_sign_msb_async(&source, num_blocks_to_add, streams);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let unsigned_res =
                    self.trim_radix_blocks_msb_async(&source, num_blocks_to_remove, streams);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    unsigned_res.into_inner(),
                )
            }
        } else {
            // casting from unsigned to signed
            if target_num_blocks > current_num_blocks {
                let num_blocks_to_add = target_num_blocks - current_num_blocks;
                let signed_res = self.extend_radix_with_trivial_zero_blocks_msb_async(
                    &source,
                    num_blocks_to_add,
                    streams,
                );
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            } else {
                let num_blocks_to_remove = current_num_blocks - target_num_blocks;
                let signed_res =
                    self.trim_radix_blocks_msb_async(&source, num_blocks_to_remove, streams);
                <CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(
                    signed_res.into_inner(),
                )
            }
        }
    }
    /// Returns the memory space occupied by a radix ciphertext on GPU
    pub fn get_ciphertext_size_on_gpu<T: CudaIntegerRadixCiphertext>(&self, ct: &T) -> u64 {
        (ct.as_ref().d_blocks.lwe_ciphertext_count().0
            * size_of::<u64>()
            * ct.as_ref().d_blocks.lwe_dimension().0) as u64
    }
}
