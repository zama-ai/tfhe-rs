use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaServerKey;

impl CudaServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg_1 = 12;
    /// let msg_2 = 10;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_sub(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let result = unsafe { self.unchecked_sub_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_sub_async(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result = ct_left.duplicate_async(stream);
        self.unchecked_sub_assign_async(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_sub_assign_async(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) {
        let neg = self.unchecked_neg_async(ct_right, stream);
        self.unchecked_add_assign_async(ct_left, &neg, stream);
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg_1 = 128;
    /// let msg_2 = 99;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// sks.unchecked_sub_assign(&mut d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct1.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub_assign(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_sub_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg_1 as u64);
    /// let ct2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.sub(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let result = unsafe { self.sub_async(ct_left, ct_right, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn sub_async(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result = ct_left.duplicate_async(stream);
        self.sub_assign_async(&mut result, ct_right, stream);
        result
    }

    pub fn sub_assign(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) {
        unsafe {
            self.sub_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn sub_assign_async(
        &self,
        ct_left: &mut CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
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

        self.unchecked_sub_assign_async(lhs, rhs, stream);
        self.propagate_single_carry_assign_async(lhs, stream);
    }
}
