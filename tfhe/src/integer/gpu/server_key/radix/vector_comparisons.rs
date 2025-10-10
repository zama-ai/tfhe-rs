use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicAtomicPatternKeySwitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_unchecked_all_eq_slices, cuda_backend_unchecked_contains_sub_slice, PBSType,
};

impl CudaServerKey {
    /// Compares two slices containing ciphertexts and returns an encryption of `true` if all
    /// pairs are equal, otherwise, returns an encryption of `false`.
    ///
    /// - If slices do not have the same length, false is returned
    /// - If at least one  pair (`lhs[i]`, `rhs[i]`) do not have the same number of blocks, false is
    ///   returned
    pub fn unchecked_all_eq_slices<T>(
        &self,
        lhs: &[T],
        rhs: &[T],
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        if lhs.len() != rhs.len() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);

            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        if lhs.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(1, 1, streams);

            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }
        if lhs.iter().zip(rhs.iter()).any(|(l, r)| {
            l.as_ref().d_blocks.lwe_ciphertext_count().0
                != r.as_ref().d_blocks.lwe_ciphertext_count().0
        }) {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);

            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        let CudaDynamicAtomicPatternKeySwitchingKey::Standard(computing_ks_key) =
            &self.key_switching_key
        else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_all_eq_slices(
                        streams,
                        &mut match_ct,
                        lhs,
                        rhs,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_all_eq_slices(
                        streams,
                        &mut match_ct,
                        lhs,
                        rhs,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        match_ct
    }

    /// Compares two slices containing ciphertexts and returns an encryption of `true` if all
    /// pairs are equal, otherwise, returns an encryption of `false`.
    ///
    /// - If slices do not have the same length, false is returned
    /// - If at least one  pair (`lhs[i]`, `rhs[i]`) do not have the same number of blocks, false is
    ///   returned
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///     let mut d_ctxt_vec1 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec1.push(d_ctxt_tmp);
    ///     }
    ///
    ///     let mut d_ctxt_vec2 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i%2;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec2.push(d_ctxt_tmp);
    ///     }
    ///
    ///     // Homomorphically check if two vectors of ciphertexts are equal
    ///     let d_check = sks.all_eq_slices(&d_ctxt_vec1, &d_ctxt_vec2, &streams);
    ///     
    ///     // Decrypt
    ///     let check = d_check.to_boolean_block(&streams);
    ///     let is_ok = cks.decrypt_bool(&check);
    ///     assert!(!is_ok);
    /// }
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///     let mut d_ctxt_vec1 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec1.push(d_ctxt_tmp);
    ///     }
    ///
    ///     let mut d_ctxt_vec2 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec2.push(d_ctxt_tmp);
    ///     }
    ///
    ///     // Homomorphically check if two vectors of ciphertexts are equal
    ///     let d_check = sks.all_eq_slices(&d_ctxt_vec1, &d_ctxt_vec2, &streams);
    ///     
    ///     // Decrypt
    ///     let check = d_check.to_boolean_block(&streams);
    ///     let is_ok = cks.decrypt_bool(&check);
    ///     assert!(is_ok);
    /// }
    /// ```
    pub fn all_eq_slices<T>(&self, lhs: &[T], rhs: &[T], streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs = Vec::<T>::with_capacity(lhs.len());
        let lhs = if lhs.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in lhs.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_lhs.push(temp_ct);
            }
            &tmp_lhs
        } else {
            lhs
        };

        let mut tmp_rhs = Vec::<T>::with_capacity(rhs.len());
        let rhs = if rhs.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in rhs.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_rhs.push(temp_ct);
            }
            &tmp_rhs
        } else {
            rhs
        };
        self.unchecked_all_eq_slices(lhs, rhs, streams)
    }

    /// Returns a boolean ciphertext encrypting `true` if `lhs` contains `rhs`, `false` otherwise
    pub fn unchecked_contains_sub_slice<T>(
        &self,
        lhs: &[T],
        rhs: &[T],
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        if rhs.len() > lhs.len() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);

            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        if rhs.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(1, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        let CudaDynamicAtomicPatternKeySwitchingKey::Standard(computing_ks_key) =
            &self.key_switching_key
        else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_contains_sub_slice(
                        streams,
                        &mut match_ct,
                        lhs,
                        rhs,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_contains_sub_slice(
                        streams,
                        &mut match_ct,
                        lhs,
                        rhs,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        match_ct
    }

    /// Returns a boolean ciphertext encrypting `true` if `lhs` contains `rhs`, `false` otherwise
    ///   
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///     let mut d_ctxt_vec1 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec1.push(d_ctxt_tmp);
    ///     }
    ///
    ///     let mut d_ctxt_vec2 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///     for i in 0..2 {
    ///      let msg_tmp = 8u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec2.push(d_ctxt_tmp);
    ///     }
    ///
    ///     // Homomorphically check if vectors1 contains vector2
    ///     let d_check = sks.contains_sub_slice(&d_ctxt_vec1, &d_ctxt_vec2, &streams);
    ///     
    ///     // Decrypt
    ///     let check = d_check.to_boolean_block(&streams);
    ///     let is_ok = cks.decrypt_bool(&check);
    ///     assert!(!is_ok);
    /// }
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///     let mut d_ctxt_vec1 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    ///     for i in 0..4 {
    ///      let msg_tmp = 3u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec1.push(d_ctxt_tmp);
    ///     }
    ///
    ///     let mut d_ctxt_vec2 = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///     for i in 0..2 {
    ///      let msg_tmp = 4u16 + i;
    ///      let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///      let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///      d_ctxt_vec2.push(d_ctxt_tmp);
    ///     }
    ///
    ///     // Homomorphically check if vectors1 contains vector2
    ///     let d_check = sks.contains_sub_slice(&d_ctxt_vec1, &d_ctxt_vec2, &streams);
    ///     
    ///     // Decrypt
    ///     let check = d_check.to_boolean_block(&streams);
    ///     let is_ok = cks.decrypt_bool(&check);
    ///     assert!(is_ok);
    /// }
    /// ```
    pub fn contains_sub_slice<T>(
        &self,
        lhs: &[T],
        rhs: &[T],
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs = Vec::<T>::with_capacity(lhs.len());
        let lhs = if lhs.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in lhs.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_lhs.push(temp_ct);
            }
            &tmp_lhs
        } else {
            lhs
        };

        let mut tmp_rhs = Vec::<T>::with_capacity(rhs.len());
        let rhs = if rhs.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in rhs.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_rhs.push(temp_ct);
            }
            &tmp_rhs
        } else {
            rhs
        };
        self.unchecked_contains_sub_slice(lhs, rhs, streams)
    }
}
