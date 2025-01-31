use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::gpu::unchecked_negate_integer_radix_async;
use crate::integer::server_key::radix_parallel::OutputFlag;

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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    /// let mut d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically a negation
    /// let d_res = sks.unchecked_neg(&mut d_ctxt, &streams);
    /// let res = d_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&res);
    /// assert_eq!(modulus - msg, dec);
    /// ```
    pub fn unchecked_neg<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &T,
        streams: &CudaStreams,
    ) -> T {
        let result = unsafe { self.unchecked_neg_async(ctxt, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_neg_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ctxt: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut ciphertext_out = ctxt.duplicate_async(streams);

        let info = ctxt.as_ref().info.blocks.first().unwrap();

        unchecked_negate_integer_radix_async(
            streams,
            ciphertext_out.as_mut(),
            ctxt.as_ref(),
            info.message_modulus.0 as u32,
            info.carry_modulus.0 as u32,
        );

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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    /// let mut d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Compute homomorphically a negation
    /// let d_res = sks.neg(&mut d_ctxt, &streams);
    /// let res = d_res.to_radix_ciphertext(&streams);
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
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
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
        let _carry =
            self.propagate_single_carry_assign_async(&mut res, streams, None, OutputFlag::None);
        res
    }
}
