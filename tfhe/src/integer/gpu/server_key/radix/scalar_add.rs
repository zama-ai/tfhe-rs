use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::SignedNumeric;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::scalar_addition_integer_radix_assign_async;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::prelude::CastInto;
use crate::shortint::ciphertext::NoiseLevel;

impl CudaServerKey {
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
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &mut streams);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_scalar_add(&d_ct, scalar, &mut streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn unchecked_scalar_add<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(streams) };
        self.unchecked_scalar_add_assign(&mut result, scalar, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_add_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if scalar != Scalar::ZERO {
            let bits_in_message = self.message_modulus.0.ilog2();
            let mut d_decomposed_scalar = CudaVec::<u64>::new_async(
                ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
                0,
            );
            let decomposed_scalar =
                BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message)
                    .iter_as::<u64>()
                    .take(d_decomposed_scalar.len())
                    .collect::<Vec<_>>();
            d_decomposed_scalar.copy_from_cpu_async(decomposed_scalar.as_slice(), streams, 0);

            let lwe_dimension = ct.as_ref().d_blocks.lwe_dimension();
            // If the scalar is decomposed using less than the number of blocks our ciphertext
            // has, we just don't touch ciphertext's last blocks
            scalar_addition_integer_radix_assign_async(
                streams,
                &mut ct.as_mut().d_blocks.0.d_vec,
                &d_decomposed_scalar,
                lwe_dimension,
                decomposed_scalar.len() as u32,
                self.message_modulus.0 as u32,
                self.carry_modulus.0 as u32,
            );

            ct.as_mut().info = ct.as_ref().info.after_scalar_add(scalar);
        }
    }

    pub fn unchecked_scalar_add_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_add_assign_async(ct, scalar, streams);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &mut streams);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.scalar_add(&d_ct, scalar, &mut streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct.duplicate_async(streams) };
        self.scalar_add_assign(&mut result, scalar, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn scalar_add_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, streams);
        };

        self.unchecked_scalar_add_assign_async(ct, scalar, streams);
        let _carry = self.propagate_single_carry_assign_async(ct, streams);
    }

    pub fn scalar_add_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_add_assign_async(ct, scalar, streams);
        }
        streams.synchronize();
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
        unsafe {
            result = ct_left.duplicate_async(stream);
        }
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
        unsafe {
            if !ct_left.block_carries_are_empty() {
                self.full_propagate_assign_async(ct_left, stream);
            }
        }
        self.unchecked_unsigned_overflowing_scalar_add_assign(ct_left, scalar, stream)
    }

    pub fn unchecked_unsigned_overflowing_scalar_add<Scalar>(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
    {
        let mut result;
        unsafe {
            result = ct_left.duplicate_async(stream);
        }
        let overflowed =
            self.unchecked_unsigned_overflowing_scalar_add_assign(&mut result, scalar, stream);
        (result, overflowed)
    }

    pub fn unchecked_unsigned_overflowing_scalar_add_assign<Scalar>(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u8> + CastInto<u64>,
    {
        self.unchecked_scalar_add_assign(ct_left, scalar, stream);
        let mut carry_out;
        unsafe {
            carry_out = self.propagate_single_carry_assign_async(ct_left, stream);
        }
        stream.synchronize();

        let num_scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, self.message_modulus.0.ilog2())
                .count();

        if num_scalar_blocks > ct_left.ciphertext.d_blocks.0.lwe_ciphertext_count.0 {
            let trivial: CudaUnsignedRadixCiphertext = self.create_trivial_radix(1, 1, stream);
            CudaBooleanBlock::from_cuda_radix_ciphertext(trivial.ciphertext)
        } else {
            if ct_left.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO {
                carry_out.as_mut().info = carry_out.as_ref().info.boolean_info(NoiseLevel::ZERO);
            }

            CudaBooleanBlock::from_cuda_radix_ciphertext(carry_out.ciphertext)
        }
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, num_blocks, &streams);
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
        Scalar: SignedNumeric + DecomposableInto<u64> + CastInto<u64>,
    {
        let mut tmp_lhs;
        unsafe {
            tmp_lhs = ct_left.duplicate_async(streams);
            if !tmp_lhs.block_carries_are_empty() {
                self.full_propagate_assign_async(&mut tmp_lhs, streams);
            }
        }

        let trivial: CudaSignedRadixCiphertext = self.create_trivial_radix(
            scalar,
            ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0,
            streams,
        );
        let (result, overflowed) = self.signed_overflowing_add(&tmp_lhs, &trivial, streams);

        let mut extra_scalar_block_iter =
            BlockDecomposer::new(scalar, self.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .skip(ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0);

        let extra_blocks_have_correct_value = if scalar < Scalar::ZERO {
            extra_scalar_block_iter.all(|block| block == (self.message_modulus.0 as u64 - 1))
        } else {
            extra_scalar_block_iter.all(|block| block == 0)
        };

        if extra_blocks_have_correct_value {
            (result, overflowed)
        } else {
            let trivial_one: CudaSignedRadixCiphertext = self.create_trivial_radix(1, 1, streams);
            // Scalar has more blocks so addition counts as overflowing
            (
                result,
                CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_one.ciphertext),
            )
        }
    }
}
