use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::CudaRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{apply_bivariate_lut_kb_async, PBSType};

impl CudaServerKey {
    #[allow(clippy::unused_self)]
    pub(crate) fn convert_integer_radixes_vec_to_single_integer_radix_ciphertext<T>(
        &self,
        radixes: &[T],
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let packed_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            radixes
                .iter()
                .map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );
        CudaIntegerRadixCiphertext::from(CudaRadixCiphertext {
            d_blocks: packed_list,
            info: radixes[0].as_ref().info.clone(),
        })
    }

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
        // If both are empty, return true
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

        let block_equality_lut = self.generate_lookup_table_bivariate(|l, r| u64::from(l == r));

        let packed_lhs = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            lhs.iter().map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );
        let packed_rhs = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            rhs.iter().map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );

        let num_radix_blocks = packed_rhs.lwe_ciphertext_count().0;
        let lwe_size = lhs[0].as_ref().d_blocks.0.lwe_dimension.to_lwe_size().0;
        let mut comparison_blocks: CudaUnsignedRadixCiphertext =
            self.create_trivial_radix(0, num_radix_blocks, streams);

        let mut comparisons_slice = comparison_blocks
            .as_mut()
            .d_blocks
            .0
            .d_vec
            .as_mut_slice(0..lwe_size * num_radix_blocks, 0)
            .unwrap();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    apply_bivariate_lut_kb_async(
                        streams,
                        &mut comparisons_slice,
                        &packed_lhs.0.d_vec,
                        &packed_rhs.0.d_vec,
                        block_equality_lut.acc.acc.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        num_radix_blocks as u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        self.message_modulus.0 as u32,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    apply_bivariate_lut_kb_async(
                        streams,
                        &mut comparisons_slice,
                        &packed_lhs.0.d_vec,
                        &packed_rhs.0.d_vec,
                        block_equality_lut.acc.acc.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        num_radix_blocks as u32,
                        self.message_modulus,
                        self.carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        self.message_modulus.0 as u32,
                    );
                }
            }
        }

        self.unchecked_are_all_comparisons_block_true(&comparison_blocks, streams)
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, &streams);
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
    ///     assert_eq!(is_ok, false)
    /// }
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, &streams);
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
    ///     assert_eq!(is_ok, true)
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
                let mut temp_ct = unsafe { ct.duplicate_async(streams) };
                if !temp_ct.block_carries_are_empty() {
                    unsafe {
                        self.full_propagate_assign_async(&mut temp_ct, streams);
                    }
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
                let mut temp_ct = unsafe { ct.duplicate_async(streams) };
                if !temp_ct.block_carries_are_empty() {
                    unsafe {
                        self.full_propagate_assign_async(&mut temp_ct, streams);
                    }
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

        let windows_results = lhs
            .windows(rhs.len())
            .map(|lhs_sub_slice| self.unchecked_all_eq_slices(lhs_sub_slice, rhs, streams).0)
            .collect::<Vec<_>>();
        let packed_windows_results = self
            .convert_integer_radixes_vec_to_single_integer_radix_ciphertext(
                &windows_results,
                streams,
            );
        self.unchecked_is_at_least_one_comparisons_block_true(&packed_windows_results, streams)
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, &streams);
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
    ///     assert_eq!(is_ok, false)
    /// }
    /// {
    ///     let number_of_blocks = 4;
    ///
    ///     let gpu_index = 0;
    ///     let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, &streams);
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
    ///     assert_eq!(is_ok, true)
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
                let mut temp_ct = unsafe { ct.duplicate_async(streams) };
                if !temp_ct.block_carries_are_empty() {
                    unsafe {
                        self.full_propagate_assign_async(&mut temp_ct, streams);
                    }
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
                let mut temp_ct = unsafe { ct.duplicate_async(streams) };
                if !temp_ct.block_carries_are_empty() {
                    unsafe {
                        self.full_propagate_assign_async(&mut temp_ct, streams);
                    }
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
