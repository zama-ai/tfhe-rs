use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::cuda_backend_count_bits;
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::server_key::radix_parallel::ilog2::BitValue;

impl CudaServerKey {
    /// Counts the bits of ct equal to bit_value, see [Self::count_ones]
    ///
    /// Expects ct to have clean carries
    fn unchecked_count_bits<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        bit_value: BitValue,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        assert!(
            self.message_modulus.0 == 4 && self.carry_modulus.0 == 4,
            "count_ones and count_zeros only support 2_2 parameters on GPU"
        );
        let num_bits_in_message = self.message_modulus.0.ilog2();
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;
        let min_num_blocks_to_have_32_bits = 32u32.div_ceil(num_bits_in_message) as usize;

        if num_blocks == 0 {
            return self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits, streams);
        }

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        let counter_num_blocks =
            (num_bits_in_ciphertext.ilog2() + 1).div_ceil(num_bits_in_message) as usize;

        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(min_num_blocks_to_have_32_bits, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_count_bits(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        counter_num_blocks as u32,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        self.message_modulus,
                        self.carry_modulus,
                        bit_value as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_count_bits(
                        streams,
                        result.as_mut(),
                        ct.as_ref(),
                        counter_num_blocks as u32,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        self.message_modulus,
                        self.carry_modulus,
                        bit_value as u32,
                        None,
                    );
                }
            }
        }

        result
    }

    fn count_bits<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        bit_value: BitValue,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp, streams);
            &tmp
        };
        self.unchecked_count_bits(ct, bit_value, streams)
    }

    /// Counts the bits of ct equal to BitValue::One, see [Self::count_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_count_ones<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_count_bits(ct, BitValue::One, streams)
    }

    /// Counts the bits of ct equal to BitValue::Zero, see [Self::count_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_count_zeros<T>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_count_bits(ct, BitValue::Zero, streams)
    }

    /// Returns the number of ones in the binary representation of ct
    ///
    /// Carries of ct are propagated on a copy first if needed, the result has clean
    /// carries.
    ///
    /// # Panics
    ///
    /// Panics with parameters other than 2_2, the only ones supported on GPU.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// // 4 blocks of 2 message bits, the width of an i8
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// let d_ct_res = sks.count_ones(&d_ctxt, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.count_ones());
    /// ```
    pub fn count_ones<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_bits(ct, BitValue::One, streams)
    }

    /// Returns the number of zeros in the binary representation of ct
    ///
    /// Carries of ct are propagated on a copy first if needed, the result has clean
    /// carries.
    ///
    /// # Panics
    ///
    /// Panics with parameters other than 2_2, the only ones supported on GPU.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// // 4 blocks of 2 message bits, the width of an i8
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let msg = -4i8;
    ///
    /// let ctxt = cks.encrypt_signed_radix(msg, number_of_blocks);
    ///
    /// let d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &streams);
    ///
    /// let d_ct_res = sks.count_zeros(&d_ctxt, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u32 = cks.decrypt_radix(&ct_res);
    /// assert_eq!(res, msg.count_zeros());
    /// ```
    pub fn count_zeros<T>(&self, ct: &T, streams: &CudaStreams) -> CudaUnsignedRadixCiphertext
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.count_bits(ct, BitValue::Zero, streams)
    }
}
