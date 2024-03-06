use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

impl CudaServerKey {
    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let number_of_blocks = 2;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, &mut stream);
    ///
    /// let modulus = PARAM_MESSAGE_2_CARRY_2_KS_PBS
    ///     .message_modulus
    ///     .0
    ///     .pow(number_of_blocks as u32) as u64;
    /// let clear_1: u64 = 13 % modulus;
    /// let clear_2: u64 = 4 % modulus;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt_radix(clear_1, number_of_blocks);
    /// let ctxt_2 = cks.encrypt_radix(clear_2, number_of_blocks);
    ///
    /// let mut d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &mut stream);
    /// let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &mut stream);
    ///
    /// // Compute homomorphically a multiplication
    /// let mut d_ct_res = sks.unchecked_mul(&mut d_ctxt_1, &d_ctxt_2, &mut stream);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_mul_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_mul_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        let num_blocks = ct_left.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_mul_integer_radix_classic_kb_assign_async(
                    &mut ct_left.as_mut().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension(),
                    d_bsk.input_lwe_dimension(),
                    d_bsk.polynomial_size(),
                    d_bsk.decomp_base_log(),
                    d_bsk.decomp_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    num_blocks,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_mul_integer_radix_multibit_kb_assign_async(
                    &mut ct_left.as_mut().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    d_multibit_bsk.decomp_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks,
                );
            }
        };

        ct_left.as_mut().info = ct_left.as_ref().info.after_mul();
    }

    pub fn unchecked_mul_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_mul_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let number_of_blocks = 2;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, &mut stream);
    ///
    /// let modulus = PARAM_MESSAGE_2_CARRY_2_KS_PBS
    ///     .message_modulus
    ///     .0
    ///     .pow(number_of_blocks as u32) as u64;
    /// let clear_1: u64 = 13 % modulus;
    /// let clear_2: u64 = 4 % modulus;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt_radix(clear_1, number_of_blocks);
    /// let ctxt_2 = cks.encrypt_radix(clear_2, number_of_blocks);
    ///
    /// let mut d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &mut stream);
    /// let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &mut stream);
    ///
    /// // Compute homomorphically a multiplication
    /// let mut d_ct_res = sks.mul(&mut d_ctxt_1, &d_ctxt_2, &mut stream);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn mul<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.mul_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn mul_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
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
                self.full_propagate_assign_async(ct_left, stream);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(ct_left, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
        };

        self.unchecked_mul_assign_async(lhs, rhs, stream);
        // Carries are cleaned internally in the mul algorithm
    }

    pub fn mul_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.mul_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }
}
