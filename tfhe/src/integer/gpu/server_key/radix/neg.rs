use crate::core_crypto::gpu::{negate_integer_radix_async, CudaStreams};
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &mut stream);
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
    pub fn unchecked_neg<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &T,
        stream: &CudaStreams,
    ) -> T {
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
        streams: &CudaStreams,
    ) -> T {
        let mut ciphertext_out = ctxt.duplicate_async(streams);
        let lwe_dimension = ctxt.as_ref().d_blocks.lwe_dimension();
        let lwe_ciphertext_count = ctxt.as_ref().d_blocks.lwe_ciphertext_count();

        let info = ctxt.as_ref().info.blocks.first().unwrap();

        negate_integer_radix_async(
            streams,
            &mut ciphertext_out.as_mut().d_blocks.0.d_vec,
            &ctxt.as_ref().d_blocks.0.d_vec,
            lwe_dimension,
            lwe_ciphertext_count.0 as u32,
            info.message_modulus.0 as u32,
            info.carry_modulus.0 as u32,
        );

        ciphertext_out.as_mut().info = ctxt.as_ref().info.after_neg();
        ciphertext_out
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &mut stream);
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
    pub fn neg<T: CudaIntegerRadixCiphertext>(&self, ctxt: &T, streams: &CudaStreams) -> T {
        let result = unsafe { self.neg_async(ctxt, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn neg_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut tmp_ctxt;

        let ct = if ctxt.block_carries_are_empty() {
            ctxt
        } else {
            tmp_ctxt = ctxt.duplicate_async(streams);
            self.full_propagate_assign_async(&mut tmp_ctxt, streams);
            &mut tmp_ctxt
        };

        let mut res = self.unchecked_neg_async(ct, streams);
        let _carry = self.propagate_single_carry_assign_async(&mut res, streams);
        res
    }
}
