use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CastFrom, UnsignedNumeric};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu,
    cuda_backend_get_scalar_left_shift_size_on_gpu,
    cuda_backend_get_scalar_logical_right_shift_size_on_gpu,
    cuda_backend_unchecked_scalar_arithmetic_right_shift_assign,
    cuda_backend_unchecked_scalar_left_shift_assign,
    cuda_backend_unchecked_scalar_logical_right_shift_assign, CudaServerKey,
};
use crate::integer::server_key::radix_parallel::scalar_shift::clamp_scalar_shift_amount;

impl CudaServerKey {
    #[cfg(test)]
    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
    pub(crate) fn unchecked_scalar_left_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_left_shift_assign(&mut result, shift, streams);
        result
    }

    pub(crate) fn unchecked_scalar_left_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        // Clamp to the bit count so a large amount overshifts instead of wrapping after the u32
        // cast (matches the CPU backend).
        let total_num_bits = lwe_ciphertext_count.0 as u64 * self.message_modulus.0.ilog2() as u64;
        let shift = clamp_scalar_shift_amount(shift, total_num_bits) as u32;
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
            cuda_backend_unchecked_scalar_left_shift_assign(
                streams,
                ct.as_mut(),
                shift,
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            );
        }
    }

    #[cfg(test)]
    /// Computes homomorphically a right shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
    pub(crate) fn unchecked_scalar_right_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_right_shift_assign(&mut result, shift, streams);
        result
    }

    pub(crate) fn unchecked_scalar_right_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        // Clamp to the bit count so a large amount overshifts instead of wrapping after the u32
        // cast (matches the CPU backend).
        let total_num_bits = lwe_ciphertext_count.0 as u64 * self.message_modulus.0.ilog2() as u64;
        let shift = clamp_scalar_shift_amount(shift, total_num_bits) as u32;
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
        unsafe {
            if T::IS_SIGNED {
                cuda_backend_unchecked_scalar_arithmetic_right_shift_assign(
                    streams,
                    ct.as_mut(),
                    shift,
                    &computing_ks_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    &self.bootstrapping_key,
                    computing_ks_key.params_ffi(),
                );
            } else {
                cuda_backend_unchecked_scalar_logical_right_shift_assign(
                    streams,
                    ct.as_mut(),
                    shift,
                    &computing_ks_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    &self.bootstrapping_key,
                    computing_ks_key.params_ffi(),
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }
    }

    pub fn scalar_right_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_right_shift_assign(ct, shift, streams);
    }

    /// Computes homomorphically a right shift by a scalar.
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2u32;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.scalar_right_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn scalar_right_shift<Scalar, T>(&self, ct: &T, shift: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_right_shift_assign(&mut result, shift, streams);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2u32;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.scalar_left_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn scalar_left_shift<Scalar, T>(&self, ct: &T, shift: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_left_shift_assign(&mut result, shift, streams);
        result
    }

    pub fn scalar_left_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: UnsignedNumeric + CastFrom<u64>,
        u64: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_left_shift_assign(ct, shift, streams);
    }

    pub fn get_scalar_left_shift_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };
        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key
            else {
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
            cuda_backend_get_full_propagate_assign_size_on_gpu(
                streams,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                self.message_modulus,
                self.carry_modulus,
            )
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
        let scalar_shift_mem = cuda_backend_get_scalar_left_shift_size_on_gpu(
            streams,
            self.message_modulus,
            self.carry_modulus,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            lwe_ciphertext_count.0 as u32,
        );
        full_prop_mem.max(scalar_shift_mem)
    }

    pub fn get_scalar_right_shift_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            cuda_backend_get_full_propagate_assign_size_on_gpu(
                streams,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                self.message_modulus,
                self.carry_modulus,
            )
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
        let scalar_shift_mem = if T::IS_SIGNED {
            cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu(
                streams,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            )
        } else {
            cuda_backend_get_scalar_logical_right_shift_size_on_gpu(
                streams,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            )
        };
        full_prop_mem.max(scalar_shift_mem)
    }
}
