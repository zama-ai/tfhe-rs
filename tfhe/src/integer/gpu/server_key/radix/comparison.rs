use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweCiphertextCount;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;
use crate::integer::gpu::{
    cuda_backend_get_comparison_size_on_gpu, cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_unchecked_comparison, ComparisonType, CudaServerKey,
};
use crate::shortint::ciphertext::Degree;

/// Returns true if `op` on `ct` must be computed on `ct` extended with one trivial zero block
/// in the least significant position.
///
/// The CUDA backend computes ordering comparisons, max and min on pairs of packed blocks, so
/// it needs an even number of blocks. The padding block multiplies both operands by the
/// message modulus, which keeps their order, signed or unsigned. The padding block is packed
/// with the original least significant block, so the comparison does not need an extra PBS.
pub(crate) fn needs_lsb_padding_block<T: CudaIntegerRadixCiphertext>(
    ct: &T,
    op: &ComparisonType,
) -> bool {
    ct.as_ref().d_blocks.lwe_ciphertext_count().0 % 2 == 1
        && !matches!(op, ComparisonType::EQ | ComparisonType::NE)
}

impl CudaServerKey {
    pub(crate) fn unchecked_comparison<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        op: ComparisonType,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );

        if needs_lsb_padding_block(ct_left, &op) {
            let lhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_left, 1, streams);
            let rhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_right, 1, streams);
            return self.unchecked_comparison(&lhs, &rhs, op, streams);
        }

        let block = CudaLweCiphertextList::new(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            LweCiphertextCount(1),
            self.ciphertext_modulus,
            streams,
        );
        let mut block_info = ct_left.as_ref().info.blocks[0];
        block_info.degree = Degree::new(1);
        let ct_info = vec![block_info];
        let ct_info = CudaRadixCiphertextInfo { blocks: ct_info };

        let mut result =
            CudaBooleanBlock::from_cuda_radix_ciphertext(CudaRadixCiphertext::new(block, ct_info));

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_comparison(
                streams,
                result.as_mut().as_mut(),
                ct_left.as_ref(),
                ct_right.as_ref(),
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                op,
                T::IS_SIGNED,
            );
        }

        result
    }

    pub(crate) fn unchecked_eq<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::EQ, streams)
    }

    pub(crate) fn unchecked_ne<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::NE, streams)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.eq(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 == msg2);
    /// ```
    pub fn eq<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_eq(lhs, rhs, streams)
    }

    pub(crate) fn get_comparison_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        op: ComparisonType,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = cuda_backend_get_full_propagate_assign_size_on_gpu(
            streams,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            self.message_modulus,
            self.carry_modulus,
        );
        let actual_full_prop_mem = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => 0,
            (true, false) => self.get_ciphertext_size_on_gpu(ct_right) + full_prop_mem,
            (false, true) => full_prop_mem,
            (false, false) => self.get_ciphertext_size_on_gpu(ct_right) + full_prop_mem,
        };

        // With padding, the two padded inputs, and for max and min the padded result, are alive
        // during the comparison
        let num_blocks = ct_left.as_ref().d_blocks.lwe_ciphertext_count().0;
        let (backend_num_blocks, padding_mem) = if needs_lsb_padding_block(ct_left, &op) {
            let padded_ct_mem = self.get_ciphertext_size_on_gpu(ct_left) / num_blocks as u64
                * (num_blocks + 1) as u64;
            let num_padded_cts = if matches!(op, ComparisonType::MAX | ComparisonType::MIN) {
                3
            } else {
                2
            };
            (num_blocks + 1, num_padded_cts * padded_ct_mem)
        } else {
            (num_blocks, 0)
        };
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        assert_eq!(
            computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.input_lwe_dimension(),
            "KS key output LWE dimension mismatch with BSK input LWE dimension"
        );
        assert_eq!(
            computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.output_lwe_dimension(),
            "KS key input LWE dimension mismatch with BSK big LWE dimension"
        );
        let comparison_mem = cuda_backend_get_comparison_size_on_gpu(
            streams,
            self.message_modulus,
            self.carry_modulus,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            backend_num_blocks as u32,
            op,
            T::IS_SIGNED,
        );
        actual_full_prop_mem.max(comparison_mem + padding_mem)
    }

    /// Compares for non equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs != rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.ne(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 != msg2);
    /// ```
    pub fn ne<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ne(lhs, rhs, streams)
    }

    pub(crate) fn unchecked_gt<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::GT, streams)
    }

    pub(crate) fn unchecked_ge<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::GE, streams)
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.gt(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 > msg2);
    /// ```
    pub fn gt<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_gt(lhs, rhs, streams)
    }

    /// Compares if lhs is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs >= rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 97u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.ge(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 >= msg2);
    /// ```
    pub fn ge<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ge(lhs, rhs, streams)
    }

    pub(crate) fn unchecked_lt<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::LT, streams)
    }

    /// Compares if lhs is lower than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.lt(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 < msg2);
    /// ```
    pub fn lt<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_lt(lhs, rhs, streams)
    }

    pub(crate) fn unchecked_le<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison(ct_left, ct_right, ComparisonType::LE, streams)
    }

    /// Compares if lhs is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// let d_ct_res = sks.le(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 < msg2);
    /// ```
    pub fn le<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_le(lhs, rhs, streams)
    }

    pub fn get_eq_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::EQ, streams)
    }

    pub fn get_ne_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::NE, streams)
    }

    pub fn get_gt_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::GT, streams)
    }

    pub fn get_ge_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::GE, streams)
    }

    pub fn get_lt_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::LT, streams)
    }

    pub fn get_le_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::LE, streams)
    }

    pub(crate) fn unchecked_max<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );

        if needs_lsb_padding_block(ct_left, &ComparisonType::MAX) {
            let lhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_left, 1, streams);
            let rhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_right, 1, streams);
            let result = self.unchecked_max(&lhs, &rhs, streams);
            return self.trim_radix_blocks_lsb(&result, 1, streams);
        }

        let mut result = ct_left.duplicate(streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_comparison(
                streams,
                result.as_mut(),
                ct_left.as_ref(),
                ct_right.as_ref(),
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                ComparisonType::MAX,
                T::IS_SIGNED,
            );
        }
        result
    }

    pub(crate) fn unchecked_min<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );

        if needs_lsb_padding_block(ct_left, &ComparisonType::MIN) {
            let lhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_left, 1, streams);
            let rhs = self.extend_radix_with_trivial_zero_blocks_lsb(ct_right, 1, streams);
            let result = self.unchecked_min(&lhs, &rhs, streams);
            return self.trim_radix_blocks_lsb(&result, 1, streams);
        }

        let mut result = ct_left.duplicate(streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_comparison(
                streams,
                result.as_mut(),
                ct_left.as_ref(),
                ct_right.as_ref(),
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                ComparisonType::MIN,
                T::IS_SIGNED,
            );
        }
        result
    }

    pub fn max<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };
        self.unchecked_max(lhs, rhs, streams)
    }

    pub fn min<T>(&self, ct_left: &T, ct_right: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(streams);
                self.full_propagate_assign(&mut tmp_lhs, streams);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(streams);
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(&mut tmp_lhs, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };
        self.unchecked_min(lhs, rhs, streams)
    }

    pub fn get_max_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::MAX, streams)
    }

    pub fn get_min_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_comparison_size_on_gpu(ct_left, ct_right, ComparisonType::MIN, streams)
    }
}
