use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::server_key::CudaServerKey;

impl CudaServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.add(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add(
        &self,
        ct_left: &CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.add_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn add_assign_async(
        &self,
        ct_left: &mut CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
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
        self.unchecked_add_assign_async(lhs, rhs, stream);
        self.propagate_single_carry_assign_async(lhs, stream);
    }

    pub fn add_assign(
        &self,
        ct_left: &mut CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
        stream: &CudaStream,
    ) {
        unsafe {
            self.add_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 10;
    /// let msg2 = 127;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_add(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn unchecked_add(
        &self,
        ct_left: &CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_add_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_add_assign_async(
        &self,
        ct_left: &mut CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
        stream: &CudaStream,
    ) {
        assert_eq!(
            ct_left.d_blocks.lwe_dimension(),
            ct_right.d_blocks.lwe_dimension(),
            "Mismatched lwe dimension between ct_left ({:?}) and ct_right ({:?})",
            ct_left.d_blocks.lwe_dimension(),
            ct_right.d_blocks.lwe_dimension()
        );

        assert_eq!(
            ct_left.d_blocks.ciphertext_modulus(),
            ct_right.d_blocks.ciphertext_modulus(),
            "Mismatched moduli between ct_left ({:?}) and ct_right ({:?})",
            ct_left.d_blocks.ciphertext_modulus(),
            ct_right.d_blocks.ciphertext_modulus()
        );

        let lwe_dimension = ct_left.d_blocks.lwe_dimension();
        let lwe_ciphertext_count = ct_left.d_blocks.lwe_ciphertext_count();

        stream.unchecked_add_integer_radix_assign_async(
            &mut ct_left.d_blocks.0.d_vec,
            &ct_right.d_blocks.0.d_vec,
            lwe_dimension,
            lwe_ciphertext_count.0 as u32,
        );

        ct_left.info = ct_left.info.after_add(&ct_right.info);
    }

    pub fn unchecked_add_assign(
        &self,
        ct_left: &mut CudaRadixCiphertext,
        ct_right: &CudaRadixCiphertext,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_add_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }
}
