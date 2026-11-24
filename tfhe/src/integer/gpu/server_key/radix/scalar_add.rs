use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::SignedNumeric;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaDynamicKeyswitchingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_get_propagate_single_carry_assign_size_on_gpu,
    cuda_backend_scalar_addition_assign,
};
use crate::integer::server_key::radix_parallel::scalar_add::ScalarOverflowFlagSource;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::prelude::CastInto;
use crate::shortint::ciphertext::NoiseLevel;

impl CudaServerKey {
    /// Turns the overflow flag computed by an overflowing scalar addition or subtraction, on the
    /// scalar truncated to the radix width, into the final one (see [`ScalarOverflowFlagSource`]).
    pub(crate) fn scalar_overflow_flag(
        &self,
        flag_source: ScalarOverflowFlagSource,
        fhe_flag: CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock {
        match flag_source {
            ScalarOverflowFlagSource::TriviallyTrue => {
                let trivial_one: CudaUnsignedRadixCiphertext =
                    self.create_trivial_radix(1, 1, streams);
                CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_one.ciphertext)
            }
            ScalarOverflowFlagSource::InvertedFhe => {
                let mut flag = fhe_flag;
                self.boolean_bitnot_assign(&mut flag, streams);
                flag
            }
            ScalarOverflowFlagSource::Fhe => fhe_flag,
        }
    }

    #[cfg(test)]
    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    pub(crate) fn unchecked_scalar_add<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_add_assign(&mut result, scalar, streams);
        result
    }

    pub(crate) fn unchecked_scalar_add_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if scalar != Scalar::ZERO {
            let decomposed_scalar =
                BlockDecomposer::with_early_stop_at_zero(scalar, self.message_modulus.0.ilog2())
                    .iter_as::<u64>()
                    .take(ct.as_ref().d_blocks.lwe_ciphertext_count().0)
                    .collect::<Vec<_>>();
            // If the scalar is decomposed using less than the number of blocks our ciphertext
            // has, we just don't touch ciphertext's last blocks
            self.unchecked_scalar_blocks_add_assign(ct, &decomposed_scalar, streams);
        }
    }

    /// Adds the blocks of an already decomposed scalar to the first blocks of `ct`.
    fn unchecked_scalar_blocks_add_assign<T>(
        &self,
        ct: &mut T,
        decomposed_scalar: &[u64],
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;
        assert!(
            decomposed_scalar.len() <= num_blocks,
            "the scalar has {} blocks, the radix only {num_blocks}",
            decomposed_scalar.len()
        );
        let mut d_decomposed_scalar = unsafe { CudaVec::<u64>::new_async(num_blocks, streams, 0) };
        unsafe {
            d_decomposed_scalar.copy_from_cpu_async(decomposed_scalar, streams, 0);
            cuda_backend_scalar_addition_assign(
                streams,
                ct.as_mut(),
                &d_decomposed_scalar,
                decomposed_scalar,
                decomposed_scalar.len() as u32,
                self.message_modulus.0 as u32,
                self.carry_modulus.0 as u32,
            );
        }
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.scalar_add(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add<Scalar, T>(&self, ct: &T, scalar: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_add_assign(&mut result, scalar, streams);
        result
    }

    pub fn get_scalar_add_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_scalar_add_assign_size_on_gpu(ct, streams)
    }

    pub fn scalar_add_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        // FIXME(gpu): CPU default ops clean their inputs with `is_clean` (carries and noise level)
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_add_assign(ct, scalar, streams);
        let _carry = self.propagate_single_carry_assign(ct, streams, None, OutputFlag::None);
    }

    pub fn get_scalar_add_assign_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            cuda_backend_get_full_propagate_assign_size_on_gpu(
                streams,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32,
                self.message_modulus,
                self.carry_modulus,
            )
        };

        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let single_carry_mem = cuda_backend_get_propagate_single_carry_assign_size_on_gpu(
            streams,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            num_blocks,
            self.message_modulus,
            self.carry_modulus,
            OutputFlag::None,
        );
        full_prop_mem.max(single_carry_mem)
    }

    pub fn unsigned_overflowing_scalar_add<Scalar>(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
    {
        let mut result;
        result = ct_left.duplicate(stream);
        let overflowed = self.unsigned_overflowing_scalar_add_assign(&mut result, scalar, stream);
        (result, overflowed)
    }

    pub fn unsigned_overflowing_scalar_add_assign<Scalar>(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
    {
        // FIXME(gpu): CPU default ops clean their inputs with `is_clean` (carries and noise level)
        if !ct_left.block_carries_are_empty() {
            self.full_propagate_assign(ct_left, stream);
        }
        self.unchecked_unsigned_overflowing_scalar_add_assign(ct_left, scalar, stream)
    }

    pub(crate) fn unchecked_unsigned_overflowing_scalar_add_assign<Scalar>(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
    {
        let num_blocks = ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0;
        let flag_source =
            ScalarOverflowFlagSource::for_unsigned_radix(scalar, num_blocks, self.message_modulus);

        if scalar != Scalar::ZERO {
            // Sign extended (or zero extended) to the radix width when the scalar is narrower: a
            // negative scalar narrower than the radix also changes the radix blocks above its width
            let decomposed_scalar = BlockDecomposer::with_block_count(
                scalar,
                self.message_modulus.0.ilog2(),
                num_blocks,
            )
            .iter_as::<u64>()
            .collect::<Vec<_>>();
            self.unchecked_scalar_blocks_add_assign(ct_left, &decomposed_scalar, stream);
        }
        let mut carry_out;
        carry_out = self.propagate_single_carry_assign(ct_left, stream, None, OutputFlag::Carry);

        if ct_left.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO {
            carry_out.as_mut().info = carry_out.as_ref().info.boolean_info(NoiseLevel::ZERO);
        }

        // The carry out is the flag of the addition with the scalar truncated to the radix
        // width, which is only exact for scalars in the radix range
        self.scalar_overflow_flag(
            flag_source,
            CudaBooleanBlock::from_cuda_radix_ciphertext(carry_out.ciphertext),
            stream,
        )
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg: i8 = 120;
    /// let scalar: i8 = 8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &streams);
    ///
    /// // Compute homomorphically an overflowing addition:
    /// let (d_ct_res, d_ct_overflowed) = sks.signed_overflowing_scalar_add(&d_ct1, scalar, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    /// let ct_overflowed = d_ct_overflowed.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i8 = cks.decrypt_signed(&ct_res);
    /// let dec_overflowed: bool = cks.decrypt_bool(&ct_overflowed);
    /// let (clear_result, clear_overflowed) = msg.overflowing_add(scalar);
    /// assert_eq!(dec_result, clear_result);
    /// assert_eq!(dec_overflowed, clear_overflowed);
    /// ```
    pub fn signed_overflowing_scalar_add<Scalar>(
        &self,
        ct_left: &CudaSignedRadixCiphertext,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u64> + DecomposableInto<u8> + CastInto<u64>,
    {
        let mut tmp_lhs;
        tmp_lhs = ct_left.duplicate(streams);
        // FIXME(gpu): CPU default ops clean their inputs with `is_clean` (carries and noise level)
        if !tmp_lhs.block_carries_are_empty() {
            self.full_propagate_assign(&mut tmp_lhs, streams);
        }

        // The scalar is truncated (or sign extended) to the radix width: the result is exact,
        // but the overflow flag is only exact for scalars in the radix range
        let num_blocks = ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0;
        let trivial: CudaSignedRadixCiphertext =
            self.create_trivial_radix(scalar, num_blocks, streams);
        let (result, overflowed) = self.signed_overflowing_add(&tmp_lhs, &trivial, streams);

        let flag_source =
            ScalarOverflowFlagSource::for_signed_radix(scalar, num_blocks, self.message_modulus);
        let overflowed = self.scalar_overflow_flag(flag_source, overflowed, streams);
        (result, overflowed)
    }
}
