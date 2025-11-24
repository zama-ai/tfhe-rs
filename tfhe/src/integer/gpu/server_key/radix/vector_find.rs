use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweBskGroupingFactor, UnsignedInteger};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_compute_final_index_from_selectors,
    cuda_backend_get_unchecked_match_value_or_size_on_gpu,
    cuda_backend_get_unchecked_match_value_size_on_gpu, cuda_backend_unchecked_contains,
    cuda_backend_unchecked_contains_clear, cuda_backend_unchecked_first_index_in_clears,
    cuda_backend_unchecked_first_index_of, cuda_backend_unchecked_first_index_of_clear,
    cuda_backend_unchecked_index_in_clears, cuda_backend_unchecked_index_of,
    cuda_backend_unchecked_is_in_clears, cuda_backend_unchecked_match_value,
    cuda_backend_unchecked_match_value_or, PBSType,
};
pub use crate::integer::server_key::radix_parallel::MatchValues;
use crate::prelude::CastInto;
use std::hash::Hash;

impl CudaServerKey {
    pub fn unchecked_match_value<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if matches.get_values().is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }

        let max_output_value = matches
            .get_values()
            .iter()
            .copied()
            .max_by(|(_, outputl), (_, outputr)| outputl.cmp(outputr))
            .expect("luts is not empty at this point")
            .1;

        let num_output_unpacked_blocks =
            self.num_blocks_to_represent_unsigned_value(max_output_value);

        let mut result_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_output_unpacked_blocks, streams);
        let mut result_bool: CudaBooleanBlock = CudaBooleanBlock(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams),
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_match_value(
                        streams,
                        &mut result_ct,
                        &mut result_bool,
                        ct.as_ref(),
                        matches,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_match_value(
                        streams,
                        &mut result_ct,
                        &mut result_bool,
                        ct.as_ref(),
                        matches,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (result_ct, result_bool)
    }

    pub fn get_unchecked_match_value_size_on_gpu<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        streams: &CudaStreams,
    ) -> u64
    where
        Clear:
            UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + CastInto<u64> + Sync + Send,
    {
        if matches.get_values().is_empty() {
            return 0;
        }

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_unchecked_match_value_size_on_gpu(
                    streams,
                    ct.as_ref(),
                    matches,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_unchecked_match_value_size_on_gpu(
                    streams,
                    ct.as_ref(),
                    matches,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    None,
                )
            }
        }
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// Returns a boolean block that encrypts `true` if the input `ct`
    /// matched one of the possible inputs
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::MatchValues;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     &streams,
    /// );
    ///
    /// let msg = 1u16;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    /// let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// let match_values = MatchValues::new(vec![
    ///     (0u16, 3u16), // map 0 to 3
    ///     (1u16, 234u16),
    ///     (2u16, 123u16),
    /// ])
    /// .unwrap();
    /// // Homomorphically match the value or return the default value
    /// let (d_ct_res, d_check) = sks.match_value(&d_ctxt, &match_values, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert_eq!(res, 234u16);
    /// assert!(is_ok);
    /// ```
    pub fn match_value<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if ct.block_carries_are_empty() {
            self.unchecked_match_value(ct, matches, streams)
        } else {
            let mut clone = ct.duplicate(streams);
            self.full_propagate_assign(&mut clone, streams);
            self.unchecked_match_value(&clone, matches, streams)
        }
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    ///
    /// If none of the input matched the `ct` then, `ct` will encrypt the
    /// value given to `or_value`
    pub fn unchecked_match_value_or<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + CastInto<u64>,
    {
        if matches.get_values().is_empty() {
            let num_blocks = self.num_blocks_to_represent_unsigned_value(or_value);
            let ct: CudaUnsignedRadixCiphertext =
                self.create_trivial_radix(or_value, num_blocks, streams);
            return ct;
        }

        let max_output_value_match = matches
            .get_values()
            .iter()
            .copied()
            .max_by(|(_, outputl), (_, outputr)| outputl.cmp(outputr))
            .expect("luts is not empty at this point")
            .1;

        let num_blocks_match = self.num_blocks_to_represent_unsigned_value(max_output_value_match);
        let num_blocks_or = self.num_blocks_to_represent_unsigned_value(or_value);
        let final_num_blocks = num_blocks_match.max(num_blocks_or);

        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(final_num_blocks, streams);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_match_value_or(
                        streams,
                        &mut result,
                        ct.as_ref(),
                        matches,
                        or_value,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_match_value_or(
                        streams,
                        &mut result,
                        ct.as_ref(),
                        matches,
                        or_value,
                        self.message_modulus,
                        self.carry_modulus,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        result
    }

    pub fn get_unchecked_match_value_or_size_on_gpu<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
        streams: &CudaStreams,
    ) -> u64
    where
        Clear:
            UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + CastInto<u64> + Sync + Send,
    {
        if matches.get_values().is_empty() {
            return 0;
        }

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_unchecked_match_value_or_size_on_gpu(
                    streams,
                    ct.as_ref(),
                    matches,
                    or_value,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_unchecked_match_value_or_size_on_gpu(
                    streams,
                    ct.as_ref(),
                    matches,
                    or_value,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    None,
                )
            }
        }
    }

    /// `match` an input value to an output value
    ///
    /// - Input values are not required to span all possible values that `ct` could hold.
    ///
    /// - The output radix has a number of blocks that depends on the maximum possible output value
    ///   from the `MatchValues`
    ///
    /// If none of the input matched the `ct` then, `ct` will encrypt the
    /// value given to `or_value`
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::MatchValues;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    ///  let number_of_blocks = 4;
    ///
    ///  let gpu_index = 0;
    ///  let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///  // Generate the client key and the server key:
    ///  let (cks, sks) =
    ///  gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///  let msg = 17u16;
    ///
    ///  // Encrypt two messages
    ///  let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    ///  let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    ///  let match_values = MatchValues::new(vec![
    ///     (0u16, 3u16), // map 0 to 3
    ///     (1u16, 234u16),
    ///     (2u16, 123u16),
    ///  ])
    ///  .unwrap();
    ///
    ///  let default_value = 25u16;
    ///
    ///  // Homomorphically match the value or return the default value
    ///  let d_ct_res = sks.match_value_or(&d_ctxt, &match_values, default_value, &streams);
    ///
    ///  // Decrypt
    ///  let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///  let res: u16 = cks.decrypt_radix(&ct_res);
    ///  assert_eq!(res, default_value)
    /// ```
    pub fn match_value_or<Clear>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        matches: &MatchValues<Clear>,
        or_value: Clear,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext
    where
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if ct.block_carries_are_empty() {
            self.unchecked_match_value_or(ct, matches, or_value, streams)
        } else {
            let mut clone = ct.duplicate(streams);
            self.full_propagate_assign(&mut clone, streams);
            self.unchecked_match_value_or(&clone, matches, or_value, streams)
        }
    }

    // /// Returns an encrypted `true` if the encrypted `value` is found in the encrypted slice
    pub fn unchecked_contains<T>(
        &self,
        cts: &[T],
        value: &T,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        if cts.is_empty() {
            let d_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            return CudaBooleanBlock::from_cuda_radix_ciphertext(d_ct.ciphertext);
        }

        let mut result = CudaBooleanBlock::from_cuda_radix_ciphertext(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams)
                .into_inner(),
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_contains(
                        streams,
                        &mut result,
                        cts,
                        value.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_contains(
                        streams,
                        &mut result,
                        cts,
                        value.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
        result
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the encrypted slice
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    ///  let number_of_blocks = 4;
    ///
    ///  let gpu_index = 0;
    ///  let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    ///  // Generate the client key and the server key:
    ///  let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    ///  let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    ///  for i in 0..4 {
    ///     let msg_tmp = 3u16 + i;
    ///     let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///     let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///     d_ctxt_vec.push(d_ctxt_tmp);
    ///  }
    ///  let msg = 6u16;
    ///  let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    ///  let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///  // Homomorphically check if a vector of ciphertexts contains a ciphertext
    ///  let d_check = sks.contains(&d_ctxt_vec, &d_ctxt, &streams);
    ///
    ///  // Decrypt
    ///  let check = d_check.to_boolean_block(&streams);
    ///  let is_ok = cks.decrypt_bool(&check);
    ///  assert!(is_ok);
    /// ```
    pub fn contains<T>(&self, cts: &[T], value: &T, streams: &CudaStreams) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }

            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.duplicate(streams);
            self.full_propagate_assign(&mut tmp_value, streams);
            &tmp_value
        };

        self.unchecked_contains(cts, value, streams)
    }

    /// Returns an encrypted `true` if the clear `value` is found in the encrypted slice
    pub fn unchecked_contains_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Clear: DecomposableInto<u64>,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        let mut result = CudaBooleanBlock::from_cuda_radix_ciphertext(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams)
                .into_inner(),
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_contains_clear(
                        streams,
                        &mut result,
                        cts,
                        clear,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_contains_clear(
                        streams,
                        &mut result,
                        cts,
                        clear,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
        result
    }

    /// Returns an encrypted `true` if the clear `value` is found in the encrypted slice
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let msg_tmp = 3u16 + i;
    ///  let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///  let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///  d_ctxt_vec.push(d_ctxt_tmp);
    /// }
    /// let msg = 6u16;
    /// // Homomorphically check if a vector of ciphertexts contains a clear value
    /// let d_check = sks.contains_clear(&d_ctxt_vec, msg, &streams);
    ///
    /// // Decrypt
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert!(is_ok);
    /// ```
    pub fn contains_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Clear: DecomposableInto<u64>,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());
        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }
            &tmp_cts
        } else {
            cts
        };

        self.unchecked_contains_clear(cts, clear, streams)
    }

    // /// Returns an encrypted `true` if the encrypted `value` is found in the clear slice
    pub fn unchecked_is_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        if clears.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }

        let ct_res: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
        let mut boolean_res = CudaBooleanBlock::from_cuda_radix_ciphertext(ct_res.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_is_in_clears(
                        streams,
                        &mut boolean_res,
                        ct.as_ref(),
                        clears,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_is_in_clears(
                        streams,
                        &mut boolean_res,
                        ct.as_ref(),
                        clears,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
        boolean_res
    }

    /// Returns an encrypted `true` if the encrypted `value` is found in the clear slice
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut clears = Vec::<u16>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let clear_tmp = 3u16 + i;
    ///  clears.push(clear_tmp);
    /// }
    /// let msg = 6u16;
    /// let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    /// let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Homomorphically check if a vector of clears contains a ciphertext
    /// let d_check = sks.is_in_clears(&d_ctxt, &clears, &streams);
    ///
    /// // Decrypt
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert!(is_ok);
    /// ```
    pub fn is_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp_ct, streams);
            &tmp_ct
        };
        self.unchecked_is_in_clears(ct, clears, streams)
    }

    /// Returns the encrypted index of the encrypted `value` in the clear slice
    /// also returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::unchecked_first_index_in_clears])
    pub fn unchecked_index_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        if clears.is_empty() {
            let trivial_ct2: CudaUnsignedRadixCiphertext = self.create_trivial_radix(
                0,
                ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            );
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct2, trivial_bool);
        }

        let num_clears = clears.len();
        let num_blocks_index =
            (num_clears.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_index, streams);

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_index_in_clears(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        ct.as_ref(),
                        clears,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_index_in_clears(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        ct.as_ref(),
                        clears,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }

    /// Returns the encrypted index of the encrypted `value` in the clear slice
    /// also returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use [Self::index_in_clears])
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    ///
    /// # Example
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut clears = Vec::<u16>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let clear_tmp = 3u16 + i;
    ///  clears.push(clear_tmp);
    /// }
    /// let msg = 6u16;
    /// let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    /// let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Homomorphically get the index if a vector of ciphertexts contains a ciphertext
    /// let (d_ct_res, d_check) = sks.index_in_clears(&d_ctxt, &clears, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert_eq!(res, 3);
    /// assert!(is_ok);
    /// ```
    pub fn index_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp_ct, streams);
            streams.synchronize();
            &tmp_ct
        };

        self.unchecked_index_in_clears(ct, clears, streams)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the clear
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Hash + Sync + Send,
    {
        if clears.is_empty() {
            let trivial_ct2: CudaUnsignedRadixCiphertext = self.create_trivial_radix(
                0,
                ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                streams,
            );
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct2, trivial_bool);
        }

        let num_blocks_result =
            (clears.len().ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_result, streams);

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_first_index_in_clears(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        ct.as_ref(),
                        clears,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_first_index_in_clears(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        ct.as_ref(),
                        clears,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the clear
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    ///
    /// # Example
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut clears = Vec::<u16>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let clear_tmp =  3u16 + i%2;
    ///  clears.push(clear_tmp);
    /// }
    /// let msg = 4u16;
    /// let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    /// let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Homomorphically get first index if a vector of ciphertexts contains a ciphertext
    /// let (d_ct_res, d_check) = sks.first_index_in_clears(&d_ctxt, &clears, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert_eq!(res, 1);
    /// assert!(is_ok);
    /// ```
    pub fn first_index_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Hash + Sync + Send,
    {
        let mut tmp_ct;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.duplicate(streams);
            self.full_propagate_assign(&mut tmp_ct, streams);
            streams.synchronize();
            &tmp_ct
        };

        self.unchecked_first_index_in_clears(ct, clears, streams)
    }

    pub fn unchecked_index_of<T>(
        &self,
        cts: &[T],
        value: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }

        let num_inputs = cts.len();
        let num_blocks_index =
            (num_inputs.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_index, streams);

        let trivial_bool: CudaUnsignedRadixCiphertext = self.create_trivial_zero_radix(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_index_of(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        value.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_index_of(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        value.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }

    /// Returns the encrypted index of the of encrypted `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use [Self::first_index_of])
    /// - If the encrypted value is not in the encrypted slice, the returned index is 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let msg_tmp = 3u16 + i;
    ///  let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///  let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///  d_ctxt_vec.push(d_ctxt_tmp);
    /// }
    /// let msg = 4u16;
    ///  let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    ///  let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Homomorphically get index if a vector of ciphertexts contains a ciphertext
    /// let (d_ct_res, d_check) = sks.index_of(&d_ctxt_vec, &d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    ///
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert_eq!(res, 1u16);
    /// assert!(is_ok);
    /// ```
    pub fn index_of<T>(
        &self,
        cts: &[T],
        value: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }

            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.duplicate(streams);
            self.full_propagate_assign(&mut tmp_value, streams);
            &tmp_value
        };
        self.unchecked_index_of(cts, value, streams)
    }

    /// Returns the encrypted index of the of clear `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use
    ///   [Self::unchecked_first_index_of_clear])
    /// - If the clear value is not in the encrypted slice, the returned index is 0
    pub fn unchecked_index_of_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }
        let selectors = cts
            .iter()
            .map(|ct| self.scalar_eq(ct, clear, streams))
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(&selectors, streams)
    }

    /// Returns the encrypted index of the of clear `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use [Self::first_index_of_clear])
    /// - If the clear value is not in the encrypted slice, the returned index is 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let msg_tmp = 3u16 + i;
    ///  let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///  let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///  d_ctxt_vec.push(d_ctxt_tmp);
    /// }
    ///
    /// let clear = 4u16;
    /// // Homomorphically get index if a vector of ciphertexts contains a clear
    /// let (d_ct_res, d_check) = sks.index_of_clear(&d_ctxt_vec, clear, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    ///
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    ///
    /// assert_eq!(res, 1u16);
    /// assert!(is_ok);
    /// ```
    pub fn index_of_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }

            &tmp_cts
        } else {
            cts
        };
        self.unchecked_index_of_clear(cts, clear, streams)
    }

    /// Returns the encrypted index of the _first_ occurrence of clear `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the clear value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_of_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }

        let num_inputs = cts.len();
        let num_blocks_result =
            (num_inputs.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_result, streams);

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_first_index_of_clear(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        clear,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_first_index_of_clear(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        clear,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }

    /// Returns the encrypted index of the _first_ occurrence of clear `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was
    /// found.
    ///
    /// # Notes
    ///
    /// - If the clear value is not in the clear slice, the returned index is 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let msg_tmp = 3u16 + i%2;
    ///  let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///  let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///  d_ctxt_vec.push(d_ctxt_tmp);
    /// }
    /// let clear = 4u16;
    /// // Homomorphically get first index if a vector of ciphertexts contains a clear
    /// let (d_ct_res, d_check) = sks.first_index_of_clear(&d_ctxt_vec, clear, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    ///
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    /// assert_eq!(res, 1u16);
    /// assert!(is_ok);
    /// ```
    pub fn first_index_of_clear<T, Clear>(
        &self,
        cts: &[T],
        clear: Clear,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize> + Sync + Send,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }

            &tmp_cts
        } else {
            cts
        };
        self.unchecked_first_index_of_clear(cts, clear, streams)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_first_index_of<T>(
        &self,
        cts: &[T],
        value: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);

            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }

        let num_inputs = cts.len();
        let num_blocks_result =
            (num_inputs.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_result, streams);

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_first_index_of(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        value.as_ref(),
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_first_index_of(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        cts,
                        value.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }

    /// Returns the encrypted index of the _first_ occurrence of encrypted `value` in the ciphertext
    /// slice also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let number_of_blocks = 4;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let mut d_ctxt_vec = Vec::<CudaUnsignedRadixCiphertext>::with_capacity(4);
    ///
    /// for i in 0..4 {
    ///  let msg_tmp = 3u16 + i%2;
    ///  let ctxt_tmp = cks.encrypt_radix(msg_tmp, number_of_blocks);
    ///  let d_ctxt_tmp = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_tmp, &streams);
    ///  d_ctxt_vec.push(d_ctxt_tmp);
    /// }
    /// let msg = 4u16;
    ///  let ctxt = cks.encrypt_radix(msg, number_of_blocks);
    ///  let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &streams);
    ///
    /// // Homomorphically get first index if a vector of ciphertexts contains a ciphertext
    /// let (d_ct_res, d_check) = sks.first_index_of(&d_ctxt_vec, &d_ctxt, &streams);
    ///
    /// // Decrypt
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let res: u16 = cks.decrypt_radix(&ct_res);
    ///
    /// let check = d_check.to_boolean_block(&streams);
    /// let is_ok = cks.decrypt_bool(&check);
    ///
    /// assert_eq!(res, 1u16);
    /// assert!(is_ok);
    /// ```
    pub fn first_index_of<T>(
        &self,
        cts: &[T],
        value: &T,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_cts = Vec::<T>::with_capacity(cts.len());
        let mut tmp_value;

        let cts = if cts.iter().any(|ct| !ct.block_carries_are_empty()) {
            // Need a way to parallelize this step
            for ct in cts.iter() {
                let mut temp_ct = ct.duplicate(streams);
                if !temp_ct.block_carries_are_empty() {
                    self.full_propagate_assign(&mut temp_ct, streams);
                }
                tmp_cts.push(temp_ct);
            }

            &tmp_cts
        } else {
            cts
        };

        let value = if value.block_carries_are_empty() {
            value
        } else {
            tmp_value = value.duplicate(streams);
            self.full_propagate_assign(&mut tmp_value, streams);
            &tmp_value
        };
        self.unchecked_first_index_of(cts, value, streams)
    }

    fn compute_final_index_from_selectors(
        &self,
        selectors: &[CudaBooleanBlock],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock) {
        let num_inputs = selectors.len();
        let num_blocks_index =
            (num_inputs.ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let mut index_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks_index, streams);

        let trivial_bool =
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams);
        let mut match_ct = CudaBooleanBlock::from_cuda_radix_ciphertext(trivial_bool.into_inner());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_compute_final_index_from_selectors(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        selectors,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_compute_final_index_from_selectors(
                        streams,
                        index_ct.as_mut(),
                        &mut match_ct,
                        selectors,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        self.key_switching_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }

        (index_ct, match_ct)
    }
}
