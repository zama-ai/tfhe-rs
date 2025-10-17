use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::{
    CudaBlockInfo, CudaRadixCiphertext, CudaRadixCiphertextInfo,
};
use crate::integer::gpu::server_key::CudaServerKey;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::NoiseLevel;

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
        let vec_block_info: Vec<CudaBlockInfo> = radixes
            .iter()
            .flat_map(|ct| ct.as_ref().info.blocks.clone())
            .collect();
        let radix_info = CudaRadixCiphertextInfo {
            blocks: vec_block_info,
        };
        CudaIntegerRadixCiphertext::from(CudaRadixCiphertext {
            d_blocks: packed_list,
            info: radix_info,
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

        let packed_lhs_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            lhs.iter().map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );
        let packed_rhs_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            rhs.iter().map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );
        let num_radix_blocks = packed_rhs_list.lwe_ciphertext_count().0;
        let block_info = CudaBlockInfo {
            degree: Degree(0),
            message_modulus: lhs
                .first()
                .unwrap()
                .as_ref()
                .info
                .blocks
                .first()
                .unwrap()
                .message_modulus,
            carry_modulus: lhs
                .first()
                .unwrap()
                .as_ref()
                .info
                .blocks
                .first()
                .unwrap()
                .carry_modulus,
            atomic_pattern: lhs
                .first()
                .unwrap()
                .as_ref()
                .info
                .blocks
                .first()
                .unwrap()
                .atomic_pattern,
            noise_level: NoiseLevel::ZERO,
        };
        let info = CudaRadixCiphertextInfo {
            blocks: vec![block_info; num_radix_blocks],
        };

        let packed_lhs = CudaRadixCiphertext {
            d_blocks: packed_lhs_list,
            info: info.clone(),
        };
        let packed_rhs = CudaRadixCiphertext {
            d_blocks: packed_rhs_list,
            info,
        };

        let mut comparison_blocks: CudaUnsignedRadixCiphertext =
            self.create_trivial_radix(0, num_radix_blocks, streams);

        self.apply_bivariate_lookup_table(
            comparison_blocks.as_mut(),
            &packed_lhs,
            &packed_rhs,
            &block_equality_lut,
            0..num_radix_blocks,
            streams,
        );
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
