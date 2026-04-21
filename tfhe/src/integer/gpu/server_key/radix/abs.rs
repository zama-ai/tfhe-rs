use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::cuda_backend_unchecked_signed_abs_assign;
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};

impl CudaServerKey {
    pub fn unchecked_abs_assign<T>(&self, ct: &mut T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    assert_eq!(
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        d_bsk.input_lwe_dimension,
                        "KS key output LWE dimension mismatch with BSK input LWE dimension"
                    );
                    assert_eq!(
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        d_bsk
                            .glwe_dimension
                            .to_equivalent_lwe_dimension(d_bsk.polynomial_size),
                        "KS key input LWE dimension mismatch with BSK big LWE dimension"
                    );
                    cuda_backend_unchecked_signed_abs_assign(
                        streams,
                        ct.as_mut(),
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        num_blocks,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    assert_eq!(
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        d_multibit_bsk.input_lwe_dimension,
                        "KS key output LWE dimension mismatch with BSK input LWE dimension"
                    );
                    assert_eq!(
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        d_multibit_bsk
                            .glwe_dimension
                            .to_equivalent_lwe_dimension(d_multibit_bsk.polynomial_size),
                        "KS key input LWE dimension mismatch with BSK big LWE dimension"
                    );
                    cuda_backend_unchecked_signed_abs_assign(
                        streams,
                        ct.as_mut(),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        num_blocks,
                        None,
                    );
                }
            }
        }
    }
    pub fn unchecked_abs<T>(&self, ct: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut res = ct.duplicate(streams);
        if T::IS_SIGNED {
            self.unchecked_abs_assign(&mut res, streams);
        }
        res
    }

    /// Computes homomorphically an absolute value of ciphertext encrypting integer
    /// values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
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
    /// let msg = -14i32;
    ///
    /// let ct = cks.encrypt_signed(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically an absolute value:
    /// let d_ct_res = sks.abs(&d_ct, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i32 = cks.decrypt_signed(&ct_res);
    ///
    /// let abs_msg = if msg < 0 { -msg } else { msg };
    /// assert_eq!(dec_result, abs_msg );
    /// ```
    pub fn abs<T>(&self, ct: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut res = ct.duplicate(streams);
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(&mut res, streams);
        }
        if T::IS_SIGNED {
            self.unchecked_abs_assign(&mut res, streams);
        }
        res
    }
}
