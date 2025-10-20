use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu, cuda_backend_get_mul_size_on_gpu,
    cuda_backend_unchecked_mul_assign, PBSType,
};

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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 2;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let modulus = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ///     .message_modulus
    ///     .0
    ///     .pow(number_of_blocks as u32);
    /// let clear_1: u64 = 13 % modulus;
    /// let clear_2: u64 = 4 % modulus;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt_radix(clear_1, number_of_blocks);
    /// let ctxt_2 = cks.encrypt_radix(clear_2, number_of_blocks);
    ///
    /// let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &streams);
    /// let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &streams);
    ///
    /// // Compute homomorphically a multiplication
    /// let d_ct_res = sks.unchecked_mul(&d_ctxt_1, &d_ctxt_2, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_mul<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.unchecked_mul_assign(&mut result, ct_right, streams);
        result
    }

    pub fn unchecked_mul_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        let num_blocks = ct_left.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let is_boolean_left = ct_left.holds_boolean_value();
        let is_boolean_right = ct_right.holds_boolean_value();
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_mul_assign(
                        streams,
                        ct_left.as_mut(),
                        is_boolean_left,
                        ct_right.as_ref(),
                        is_boolean_right,
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_mul_assign(
                        streams,
                        ct_left.as_mut(),
                        is_boolean_left,
                        ct_right.as_ref(),
                        is_boolean_right,
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
                        num_blocks,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 2;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let modulus = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    ///     .message_modulus
    ///     .0
    ///     .pow(number_of_blocks as u32);
    /// let clear_1: u64 = 13 % modulus;
    /// let clear_2: u64 = 4 % modulus;
    ///
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt_radix(clear_1, number_of_blocks);
    /// let ctxt_2 = cks.encrypt_radix(clear_2, number_of_blocks);
    ///
    /// let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &streams);
    /// let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &streams);
    ///
    /// // Compute homomorphically a multiplication
    /// let d_ct_res = sks.mul(&d_ctxt_1, &d_ctxt_2, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn mul<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.mul_assign(&mut result, ct_right, streams);
        result
    }

    pub fn mul_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate(streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_assign(ct_left, streams);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.duplicate(streams);

                self.full_propagate_assign(ct_left, streams);
                self.full_propagate_assign(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
        };

        self.unchecked_mul_assign(lhs, rhs, streams);
        // Carries are cleaned internally in the mul algorithm
    }

    pub fn get_mul_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );
        let full_prop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_full_propagate_assign_size_on_gpu(
                    streams,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_full_propagate_assign_size_on_gpu(
                    streams,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        let actual_full_prop_mem = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => 0,
            (true, false) => self.get_ciphertext_size_on_gpu(ct_right) + full_prop_mem,
            (false, true) => full_prop_mem,
            (false, false) => self.get_ciphertext_size_on_gpu(ct_right) + full_prop_mem,
        };

        let lwe_ciphertext_count = ct_left.as_ref().d_blocks.lwe_ciphertext_count();
        let is_boolean_left = ct_left.holds_boolean_value();
        let is_boolean_right = ct_right.holds_boolean_value();

        let mul_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_mul_size_on_gpu(
                streams,
                is_boolean_left,
                is_boolean_right,
                self.message_modulus,
                self.carry_modulus,
                d_bsk.glwe_dimension,
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                d_bsk.polynomial_size,
                d_bsk.decomp_base_log,
                d_bsk.decomp_level_count,
                self.key_switching_key.decomposition_base_log(),
                self.key_switching_key.decomposition_level_count(),
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => cuda_backend_get_mul_size_on_gpu(
                streams,
                is_boolean_left,
                is_boolean_right,
                self.message_modulus,
                self.carry_modulus,
                d_multibit_bsk.glwe_dimension,
                self.key_switching_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                d_multibit_bsk.polynomial_size,
                d_multibit_bsk.decomp_base_log,
                d_multibit_bsk.decomp_level_count,
                self.key_switching_key.decomposition_base_log(),
                self.key_switching_key.decomposition_level_count(),
                lwe_ciphertext_count.0 as u32,
                PBSType::MultiBit,
                d_multibit_bsk.grouping_factor,
                None,
            ),
        };
        actual_full_prop_mem.max(mul_mem)
    }
}
