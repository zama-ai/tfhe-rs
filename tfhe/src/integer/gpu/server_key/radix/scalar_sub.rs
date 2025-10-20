use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{Numeric, SignedNumeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::server_key::TwosComplementNegation;
use crate::prelude::CastInto;

impl CudaServerKey {
    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_scalar_sub(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn unchecked_scalar_sub<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_sub_assign(&mut result, scalar, streams);
        result
    }

    pub fn unchecked_scalar_sub_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let negated_scalar = scalar.twos_complement_negation();
        self.unchecked_scalar_add_assign(ct, negated_scalar, streams);
    }

    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.scalar_sub(&d_ct, scalar, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn scalar_sub<Scalar, T>(&self, ct: &T, scalar: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_sub_assign(&mut result, scalar, streams);
        result
    }

    pub fn get_scalar_sub_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_scalar_sub_assign_size_on_gpu(ct, streams)
    }

    pub fn scalar_sub_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_sub_assign(ct, scalar, streams);
        let _carry = self.propagate_single_carry_assign(ct, streams, None, OutputFlag::None);
    }

    pub fn get_scalar_sub_assign_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.get_scalar_add_assign_size_on_gpu(ct, streams)
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
    /// let (d_ct_res, d_ct_overflowed) = sks.signed_overflowing_scalar_sub(&d_ct1, scalar, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    /// let ct_overflowed = d_ct_overflowed.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i8 = cks.decrypt_signed(&ct_res);
    /// let dec_overflowed: bool = cks.decrypt_bool(&ct_overflowed);
    /// let (clear_result, clear_overflowed) = msg.overflowing_sub(scalar);
    /// assert_eq!(dec_result, clear_result);
    /// assert_eq!(dec_overflowed, clear_overflowed);
    /// ```
    pub fn signed_overflowing_scalar_sub<Scalar>(
        &self,
        ct_left: &CudaSignedRadixCiphertext,
        scalar: Scalar,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u64> + CastInto<u64>,
    {
        let mut tmp_lhs;
        tmp_lhs = ct_left.duplicate(streams);
        if !tmp_lhs.block_carries_are_empty() {
            self.full_propagate_assign(&mut tmp_lhs, streams);
        }

        let trivial: CudaSignedRadixCiphertext = self.create_trivial_radix(
            scalar,
            ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0,
            streams,
        );
        let (result, overflowed) = self.signed_overflowing_sub(&tmp_lhs, &trivial, streams);

        let mut extra_scalar_block_iter =
            BlockDecomposer::new(scalar, self.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .skip(ct_left.ciphertext.d_blocks.lwe_ciphertext_count().0);

        let extra_blocks_have_correct_value = if scalar < Scalar::ZERO {
            extra_scalar_block_iter.all(|block| block == (self.message_modulus.0 - 1))
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
