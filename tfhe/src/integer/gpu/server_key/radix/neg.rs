use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaServerKey;

impl CudaServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Encrypt two messages:
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
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    /// let mut d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &mut stream);
    ///
    /// // Compute homomorphically a negation
    /// let d_res = sks.unchecked_neg(&mut d_ctxt, &mut stream);
    /// let res = d_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&res);
    /// assert_eq!(modulus - msg, dec);
    /// ```
    pub fn unchecked_neg<T: CudaIntegerRadixCiphertext>(&self, ctxt: &T, stream: &CudaStream) -> T {
        let result = unsafe { self.unchecked_neg_async(ctxt, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_neg_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = ctxt.duplicate_async(stream);
        self.unchecked_neg_assign_async(&mut result, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_neg_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &mut T,
        stream: &CudaStream,
    ) {
        let ciphertext = ctxt.as_mut();
        let lwe_dimension = ciphertext.d_blocks.lwe_dimension();
        let lwe_ciphertext_count = ciphertext.d_blocks.lwe_ciphertext_count();

        let info = ciphertext.info.blocks.first().unwrap();

        stream.negate_integer_radix_assign_async(
            &mut ciphertext.d_blocks.0.d_vec,
            lwe_dimension,
            lwe_ciphertext_count.0 as u32,
            info.message_modulus.0 as u32,
            info.carry_modulus.0 as u32,
        );

        ciphertext.info = ciphertext.info.after_neg();
    }

    pub fn unchecked_neg_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &mut T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_neg_assign_async(ctxt, stream);
        }
        stream.synchronize();
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Encrypt two messages:
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
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    /// let mut d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &mut stream);
    ///
    /// // Compute homomorphically a negation
    /// let d_res = sks.neg(&mut d_ctxt, &mut stream);
    /// let res = d_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&res);
    /// assert_eq!(modulus - msg, dec);
    /// ```
    pub fn neg<T: CudaIntegerRadixCiphertext>(&self, ctxt: &T, stream: &CudaStream) -> T {
        let mut result = unsafe { ctxt.duplicate_async(stream) };
        self.neg_assign(&mut result, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn neg_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &mut T,
        stream: &CudaStream,
    ) {
        let mut tmp_ctxt;

        let ct = if ctxt.block_carries_are_empty() {
            ctxt
        } else {
            tmp_ctxt = ctxt.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_ctxt, stream);
            &mut tmp_ctxt
        };

        self.unchecked_neg_assign_async(ct, stream);
        self.propagate_single_carry_assign_async(ct, stream);
    }

    pub fn neg_assign<T: CudaIntegerRadixCiphertext>(&self, ctxt: &mut T, stream: &CudaStream) {
        unsafe {
            self.neg_assign_async(ctxt, stream);
        }
        stream.synchronize();
    }
}
