use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{CiphertextModulus, LweCiphertextCount};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{ComparisonType, CudaServerKey};
use crate::shortint::ciphertext::Degree;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_comparison_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        op: ComparisonType,
        stream: &CudaStream,
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

        let block = CudaLweCiphertextList::new(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            LweCiphertextCount(1),
            CiphertextModulus::new_native(),
            stream,
        );
        let mut block_info = ct_left.as_ref().info.blocks[0];
        block_info.degree = Degree::new(0);
        let ct_info = vec![block_info];
        let ct_info = CudaRadixCiphertextInfo { blocks: ct_info };

        let mut result =
            CudaBooleanBlock::from_cuda_radix_ciphertext(CudaRadixCiphertext::new(block, ct_info));

        let lwe_ciphertext_count = ct_left.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_comparison_integer_radix_classic_kb_async(
                    &mut result.as_mut().ciphertext.d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    lwe_ciphertext_count.0 as u32,
                    op,
                    T::IS_SIGNED,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_comparison_integer_radix_multibit_kb_async(
                    &mut result.as_mut().ciphertext.d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                    op,
                    T::IS_SIGNED,
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_eq_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result =
            self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::EQ, stream);
        result.as_mut().ciphertext.info = result.as_ref().ciphertext.info.after_eq();
        result
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_eq(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 == msg2);
    /// ```
    pub fn unchecked_eq<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_eq_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_ne_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result =
            self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::NE, stream);
        result.as_mut().ciphertext.info = result.as_ref().ciphertext.info.after_ne();
        result
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_ne(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 != msg2);
    /// ```
    pub fn unchecked_ne<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_ne_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn eq_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_eq_async(lhs, rhs, stream)
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.eq(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 == msg2);
    /// ```
    pub fn eq<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.eq_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn ne_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ne_async(lhs, rhs, stream)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs != rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.ne(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 != msg2);
    /// ```
    pub fn ne<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.ne_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_gt_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::GT, stream)
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_gt(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 > msg2);
    /// ```
    pub fn unchecked_gt<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_gt_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_ge_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::GE, stream)
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn gt_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_gt_async(lhs, rhs, stream)
    }

    pub fn gt<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.gt_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 97u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_ge(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 >= msg2);
    /// ```
    pub fn unchecked_ge<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_ge_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn ge_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ge_async(lhs, rhs, stream)
    }

    pub fn ge<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.ge_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_lt_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::LT, stream)
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_lt(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 < msg2);
    /// ```
    pub fn unchecked_lt<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_lt_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn lt_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_lt_async(lhs, rhs, stream)
    }

    pub fn lt<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.lt_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_le_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_comparison_async(ct_left, ct_right, ComparisonType::LE, stream)
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_le(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 < msg2);
    /// ```
    pub fn unchecked_le<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_le_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn le_async<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_le_async(lhs, rhs, stream)
    }

    pub fn le<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.le_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_max_async<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
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

        let mut result = ct_left.duplicate_async(stream);

        let lwe_ciphertext_count = ct_left.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_comparison_integer_radix_classic_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    lwe_ciphertext_count.0 as u32,
                    ComparisonType::MAX,
                    T::IS_SIGNED,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_comparison_integer_radix_multibit_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                    ComparisonType::MAX,
                    T::IS_SIGNED,
                );
            }
        }

        result
    }

    pub fn unchecked_max<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_max_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_min_async<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
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

        let mut result = ct_left.duplicate_async(stream);

        let lwe_ciphertext_count = ct_left.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_comparison_integer_radix_classic_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    lwe_ciphertext_count.0 as u32,
                    ComparisonType::MIN,
                    T::IS_SIGNED,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_comparison_integer_radix_multibit_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct_left.as_ref().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                    ComparisonType::MIN,
                    T::IS_SIGNED,
                );
            }
        }

        result
    }

    pub fn unchecked_min<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_min_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn max_async<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };
        self.unchecked_max_async(lhs, rhs, stream)
    }

    pub fn max<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.max_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn min_async<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
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
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate_async(stream);
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };
        self.unchecked_min_async(lhs, rhs, stream)
    }

    pub fn min<T>(&self, ct_left: &T, ct_right: &T, stream: &CudaStream) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.min_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }
}
