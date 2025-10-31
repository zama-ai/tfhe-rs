use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{LweBskGroupingFactor, UnsignedInteger};
use crate::integer::block_decomposition::{BlockDecomposer, Decomposable, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::CudaRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_aggregate_one_hot_vector, cuda_backend_compute_equality_selectors,
    cuda_backend_create_possible_results, cuda_backend_get_unchecked_match_value_size_on_gpu,
    cuda_backend_unchecked_match_value, PBSType,
};
pub use crate::integer::server_key::radix_parallel::MatchValues;
use crate::prelude::CastInto;
use itertools::Itertools;
use rayon::prelude::*;
use std::hash::Hash;

impl CudaServerKey {
    #[allow(clippy::unused_self)]
    pub(crate) fn convert_selectors_to_unsigned_radix_ciphertext(
        &self,
        selectors: &[CudaBooleanBlock],
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        if selectors.is_empty() {
            return self.create_trivial_radix(0, 1, streams);
        }
        let packed_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            selectors
                .iter()
                .map(|ciphertext| &ciphertext.0.ciphertext.d_blocks),
            streams,
        );
        let vec_block_info: Vec<CudaBlockInfo> = selectors
            .iter()
            .flat_map(|ct| ct.0.ciphertext.info.blocks.clone())
            .collect();
        let radix_info = CudaRadixCiphertextInfo {
            blocks: vec_block_info,
        };
        CudaIntegerRadixCiphertext::from(CudaRadixCiphertext {
            d_blocks: packed_list,
            info: radix_info,
        })
    }

    pub(crate) fn convert_unsigned_radix_ciphertext_to_selectors(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> Vec<CudaBooleanBlock> {
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;
        let lwe_size = ct.as_ref().d_blocks.lwe_dimension().to_lwe_size().0;
        let mut unpacked_selectors = Vec::<CudaBooleanBlock>::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let mut radix_ct: CudaUnsignedRadixCiphertext =
                self.create_trivial_radix(0, 1, streams);
            let slice_in = ct
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice(i * lwe_size..(i + 1) * lwe_size, 0)
                .unwrap();
            let mut slice_out = radix_ct
                .as_mut()
                .d_blocks
                .0
                .d_vec
                .as_mut_slice(0..lwe_size, 0)
                .unwrap();
            unsafe {
                slice_out.copy_from_gpu_async(&slice_in, streams, 0);
                streams.synchronize();
            }
            let boolean_block = CudaBooleanBlock::from_cuda_radix_ciphertext(radix_ct.into_inner());

            unpacked_selectors.push(boolean_block);
        }
        unpacked_selectors
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

        let num_input_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let num_bits_in_message = self.message_modulus.0.ilog2();

        let h_match_inputs: Vec<u64> = matches
            .get_values()
            .par_iter()
            .map(|(input, _output)| *input)
            .flat_map(|input_value| {
                BlockDecomposer::new(input_value, num_bits_in_message)
                    .take(num_input_blocks as usize)
                    .map(|block_value| block_value.cast_into())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let max_output_value = matches
            .get_values()
            .iter()
            .copied()
            .max_by(|(_, outputl), (_, outputr)| outputl.cmp(outputr))
            .expect("luts is not empty at this point")
            .1;

        let num_output_unpacked_blocks =
            self.num_blocks_to_represent_unsigned_value(max_output_value);
        let num_output_packed_blocks = num_output_unpacked_blocks.div_ceil(2) as u32;

        let h_match_outputs: Vec<u64> = matches
            .get_values()
            .par_iter()
            .map(|(_input, output)| *output)
            .flat_map(|output_value| {
                BlockDecomposer::new(output_value, 2 * num_bits_in_message)
                    .take(num_output_packed_blocks as usize)
                    .map(|block_value| block_value.cast_into())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut result_ct: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_output_unpacked_blocks, streams);
        let mut result_bool: CudaBooleanBlock = CudaBooleanBlock(
            self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams),
        );

        let max_output_is_zero = max_output_value == Clear::ZERO;
        let num_matches = matches.get_values().len() as u32;

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_match_value(
                        streams,
                        &mut result_ct,
                        &mut result_bool,
                        ct.as_ref(),
                        &h_match_inputs,
                        &h_match_outputs,
                        num_matches,
                        num_input_blocks,
                        num_output_packed_blocks,
                        max_output_is_zero,
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
                        &h_match_inputs,
                        &h_match_outputs,
                        num_matches,
                        num_input_blocks,
                        num_output_packed_blocks,
                        max_output_is_zero,
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
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if matches.get_values().is_empty() {
            return 0;
        }

        let num_input_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let max_output_value = matches
            .get_values()
            .iter()
            .copied()
            .max_by(|(_, outputl), (_, outputr)| outputl.cmp(outputr))
            .expect("luts is not empty at this point")
            .1;

        let num_output_unpacked_blocks =
            self.num_blocks_to_represent_unsigned_value(max_output_value);
        let num_output_packed_blocks = num_output_unpacked_blocks.div_ceil(2) as u32;

        let max_output_is_zero = max_output_value == Clear::ZERO;
        let num_matches = matches.get_values().len() as u32;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_unchecked_match_value_size_on_gpu(
                    streams,
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
                    num_matches,
                    num_input_blocks,
                    num_output_packed_blocks,
                    max_output_is_zero,
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_unchecked_match_value_size_on_gpu(
                    streams,
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
                    num_matches,
                    num_input_blocks,
                    num_output_packed_blocks,
                    max_output_is_zero,
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
        Clear: UnsignedInteger + DecomposableInto<u64> + CastInto<usize>,
    {
        if matches.get_values().is_empty() {
            let ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(
                or_value,
                self.num_blocks_to_represent_unsigned_value(or_value),
                streams,
            );
            return ct;
        }
        let (result, selected) = self.unchecked_match_value(ct, matches, streams);

        // The result must have as many block to represent either the result of the match or the
        // or_value
        let num_blocks_to_represent_or_value =
            self.num_blocks_to_represent_unsigned_value(or_value);
        let num_blocks = (result.as_ref().d_blocks.lwe_ciphertext_count().0)
            .max(num_blocks_to_represent_or_value);
        let or_value: CudaUnsignedRadixCiphertext =
            self.create_trivial_radix(or_value, num_blocks, streams);
        let casted_result = self.cast_to_unsigned(result, num_blocks, streams);
        // Note, this could be slightly faster when we have scalar if then_else
        self.unchecked_if_then_else(&selected, &casted_result, &or_value, streams)
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
        //Here It would be better to launch them in parallel maybe using different streams or
        // packed them in a vector
        let selectors = cts
            .iter()
            .map(|ct| self.eq(ct, value, streams))
            .collect::<Vec<_>>();

        let packed_ct = self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        self.unchecked_is_at_least_one_comparisons_block_true(&packed_ct, streams)
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
        let selectors = cts
            .iter()
            .map(|ct| self.scalar_eq(ct, clear, streams))
            .collect::<Vec<_>>();

        let packed_ct = self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        self.unchecked_is_at_least_one_comparisons_block_true(&packed_ct, streams)
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
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if clears.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return trivial_bool;
        }
        let selectors = self.compute_equality_selectors(ct, clears.par_iter().copied(), streams);

        let blocks_ct = self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        self.unchecked_is_at_least_one_comparisons_block_true(&blocks_ct, streams)
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
        Clear: DecomposableInto<u64> + CastInto<usize>,
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
    /// - If the encrypted value is not in the clear slice, the returned index is 0
    pub fn unchecked_index_in_clears<T, Clear>(
        &self,
        ct: &T,
        clears: &[Clear],
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock)
    where
        T: CudaIntegerRadixCiphertext,
        Clear: DecomposableInto<u64> + CastInto<usize>,
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
        let selectors = self.compute_equality_selectors(ct, clears.par_iter().copied(), streams);
        self.compute_final_index_from_selectors(selectors, streams)
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
        Clear: DecomposableInto<u64> + CastInto<usize>,
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
        Clear: DecomposableInto<u64> + CastInto<usize> + Hash,
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
        let unique_clears = clears
            .iter()
            .copied()
            .enumerate()
            .unique_by(|&(_, value)| value)
            .collect::<Vec<_>>();
        let selectors = self.compute_equality_selectors(
            ct,
            unique_clears.par_iter().copied().map(|(_, value)| value),
            streams,
        );

        let selectors2 = self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        let num_blocks_result =
            (clears.len().ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let possible_values = self.create_possible_results(
            num_blocks_result,
            selectors
                .into_par_iter()
                .zip(unique_clears.into_par_iter().map(|(index, _)| index as u64)),
            streams,
        );

        let out_ct = self.aggregate_one_hot_vector(&possible_values, streams);

        let block = self.unchecked_is_at_least_one_comparisons_block_true(&selectors2, streams);
        (out_ct, block)
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
        Clear: DecomposableInto<u64> + CastInto<usize> + Hash,
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

    /// Returns the encrypted index of the of encrypted `value` in the ciphertext slice
    /// also, it returns an encrypted boolean that is `true` if the encrypted value was found.
    ///
    /// # Notes
    ///
    /// - clear values in the slice must be unique (otherwise use [Self::unchecked_first_index_of])
    /// - If the encrypted value is not in the encrypted slice, the returned index is 0
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
        let selectors = cts
            .iter()
            .map(|ct| self.eq(ct, value, streams))
            .collect::<Vec<_>>();

        self.compute_final_index_from_selectors(selectors, streams)
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

        self.compute_final_index_from_selectors(selectors, streams)
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
        Clear: DecomposableInto<u64> + CastInto<usize>,
    {
        if cts.is_empty() {
            let trivial_ct: CudaUnsignedRadixCiphertext = self.create_trivial_radix(0, 1, streams);
            let trivial_bool = CudaBooleanBlock::from_cuda_radix_ciphertext(
                trivial_ct.duplicate(streams).into_inner(),
            );
            return (trivial_ct, trivial_bool);
        }
        let num_blocks_result =
            (cts.len().ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let selectors = cts
            .iter()
            .map(|ct| self.scalar_eq(ct, clear, streams))
            .collect::<Vec<_>>();

        let packed_selectors =
            self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        let mut only_first_selectors = self.only_keep_first_true(packed_selectors, streams);

        let unpacked_selectors =
            self.convert_unsigned_radix_ciphertext_to_selectors(&mut only_first_selectors, streams);

        let possible_values = self.create_possible_results(
            num_blocks_result,
            unpacked_selectors
                .into_par_iter()
                .enumerate()
                .map(|(i, v)| (v, i as u64)),
            streams,
        );
        let out_ct = self.aggregate_one_hot_vector(&possible_values, streams);

        let block =
            self.unchecked_is_at_least_one_comparisons_block_true(&only_first_selectors, streams);
        (out_ct, block)
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

        let num_blocks_result =
            (cts.len().ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let selectors = cts
            .iter()
            .map(|ct| self.eq(ct, value, streams))
            .collect::<Vec<_>>();

        let packed_selectors =
            self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);

        let mut only_first_selectors = self.only_keep_first_true(packed_selectors, streams);

        let unpacked_selectors =
            self.convert_unsigned_radix_ciphertext_to_selectors(&mut only_first_selectors, streams);

        let possible_values = self.create_possible_results(
            num_blocks_result,
            unpacked_selectors
                .into_par_iter()
                .enumerate()
                .map(|(i, v)| (v, i as u64)),
            streams,
        );
        let out_ct = self.aggregate_one_hot_vector(&possible_values, streams);

        let block =
            self.unchecked_is_at_least_one_comparisons_block_true(&only_first_selectors, streams);
        (out_ct, block)
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
        selectors: Vec<CudaBooleanBlock>,
        streams: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock) {
        let num_blocks_result =
            (selectors.len().ilog2() + 1).div_ceil(self.message_modulus.0.ilog2()) as usize;

        let selectors2 = self.convert_selectors_to_unsigned_radix_ciphertext(&selectors, streams);
        let possible_values = self.create_possible_results(
            num_blocks_result,
            selectors
                .into_par_iter()
                .enumerate()
                .map(|(i, v)| (v, i as u64)),
            streams,
        );
        let one_hot_vector = self.aggregate_one_hot_vector(&possible_values, streams);

        let block = self.unchecked_is_at_least_one_comparisons_block_true(&selectors2, streams);

        (one_hot_vector, block)
    }

    /// Computes the vector of selectors from an input iterator of clear values and an encrypted
    /// value
    ///
    /// Given an iterator of clear values, and an encrypted radix ciphertext,
    /// this method will return a vector of encrypted boolean values where
    /// each value is either 1 if the ct is equal to the corresponding clear in the iterator
    /// otherwise it will be 0.
    /// On the GPU after applying many luts the result is stored differently than on the CPU.
    /// If we have 4 many luts result is stored contiguosly in memory as follows:
    /// [result many lut 1][result many lut 2][result many lut 3][result many lut 4]
    /// In this case we need to jump between the results of the many luts to build the final result
    ///
    /// Requires ct to have empty carries
    fn compute_equality_selectors<T, Iter, Clear>(
        &self,
        ct: &T,
        possible_input_values: Iter,
        streams: &CudaStreams,
    ) -> Vec<CudaBooleanBlock>
    where
        T: CudaIntegerRadixCiphertext,
        Iter: ParallelIterator<Item = Clear>,
        Clear: Decomposable + CastInto<usize> + Send + Sync,
    {
        assert!(
            ct.block_carries_are_empty(),
            "internal error: ciphertext carries must be empty"
        );
        assert!(
            self.carry_modulus.0 >= self.message_modulus.0,
            "This function uses many LUTs in a way that requires to have at least as much carry \
            space as message space ({:?} vs {:?})",
            self.carry_modulus,
            self.message_modulus
        );

        let num_bits_in_message = self.message_modulus.0.ilog2();
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let clear_values: Vec<Clear> = possible_input_values.collect();
        let num_possible_values = clear_values.len() as u32;

        if num_possible_values == 0 {
            return vec![];
        }

        let h_decomposed_cleartexts: Vec<u64> = clear_values
            .into_par_iter()
            .flat_map(|input_value| {
                BlockDecomposer::new(input_value, num_bits_in_message)
                    .take(num_blocks as usize)
                    .map(|block_value| block_value.cast_into() as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut result_vec: Vec<CudaBooleanBlock> = (0..num_possible_values)
            .map(|_| {
                CudaBooleanBlock(
                    self.create_trivial_zero_radix::<CudaUnsignedRadixCiphertext>(1, streams),
                )
            })
            .collect();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_compute_equality_selectors(
                        streams,
                        &mut result_vec,
                        ct.as_ref(),
                        &h_decomposed_cleartexts,
                        num_possible_values,
                        num_blocks,
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
                    cuda_backend_compute_equality_selectors(
                        streams,
                        &mut result_vec,
                        ct.as_ref(),
                        &h_decomposed_cleartexts,
                        num_possible_values,
                        num_blocks,
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

        result_vec
    }

    /// Creates a vector of radix ciphertext from an iterator that associates encrypted boolean
    /// values to clear values.
    ///
    /// The elements of the resulting vector are zero if the corresponding BooleanBlock encrypted 0,
    /// otherwise it encrypts the associated clear value.
    ///
    /// This is only really useful if only one of the boolean block is known to be non-zero.
    ///
    /// `num_blocks`: number of blocks (unpacked) needed to represent the biggest clear value
    ///
    /// - Resulting radix ciphertexts have their block packed, thus they will have ceil (numb_blocks
    ///   / 2) elements
    fn create_possible_results<T, Iter, Clear>(
        &self,
        num_blocks: usize,
        possible_outputs: Iter,
        streams: &CudaStreams,
    ) -> Vec<T>
    where
        T: CudaIntegerRadixCiphertext,
        Iter: ParallelIterator<Item = (CudaBooleanBlock, Clear)>,
        Clear: Decomposable + CastInto<usize> + Send + Sync,
    {
        assert!(
            self.carry_modulus.0 >= self.message_modulus.0,
            "As this function packs blocks, it requires to have at least as much carry \
            space as message space ({:?} vs {:?})",
            self.carry_modulus,
            self.message_modulus
        );

        let num_bits_in_message = self.message_modulus.0.ilog2();
        let num_packed_blocks = num_blocks.div_ceil(2) as u32;

        let collected_outputs: Vec<(CudaBooleanBlock, Clear)> = possible_outputs.collect();
        let num_possible_values = collected_outputs.len();

        if num_possible_values == 0 {
            return vec![];
        }

        let (selectors, clear_values): (Vec<CudaBooleanBlock>, Vec<Clear>) =
            collected_outputs.into_iter().unzip();

        let h_decomposed_cleartexts: Vec<u64> = clear_values
            .into_par_iter()
            .flat_map(|input_value| {
                BlockDecomposer::new(input_value, 2 * num_bits_in_message)
                    .take(num_packed_blocks as usize)
                    .map(|block_value| block_value.cast_into() as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut result_vec: Vec<T> = (0..num_possible_values)
            .map(|_| self.create_trivial_zero_radix(num_packed_blocks as usize, streams))
            .collect();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_create_possible_results(
                        streams,
                        &mut result_vec,
                        &selectors,
                        &h_decomposed_cleartexts,
                        num_packed_blocks,
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
                    cuda_backend_create_possible_results(
                        streams,
                        &mut result_vec,
                        &selectors,
                        &h_decomposed_cleartexts,
                        num_packed_blocks,
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

        result_vec
    }

    /// Aggregate/combines a vec of one-hot vector of radix ciphertexts
    /// (i.e. at most one of the vector element is non-zero) into single ciphertext
    /// containing the non-zero value.
    ///
    /// The elements in the one hot vector have their block packed.
    ///
    /// The returned result has non packed blocks
    fn aggregate_one_hot_vector<T>(&self, one_hot_vector: &[T], streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        if one_hot_vector.is_empty() {
            return self.create_trivial_zero_radix(0, streams);
        }

        let num_packed_blocks = one_hot_vector[0].as_ref().d_blocks.lwe_ciphertext_count().0;
        let mut output_ct: T = self.create_trivial_zero_radix(num_packed_blocks * 2, streams);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_aggregate_one_hot_vector(
                        streams,
                        &mut output_ct,
                        one_hot_vector,
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
                    cuda_backend_aggregate_one_hot_vector(
                        streams,
                        &mut output_ct,
                        one_hot_vector,
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

        output_ct
    }

    /// Only keeps at most one Ciphertext that encrypts 1
    ///
    /// Given a Vec of Ciphertexts where each Ciphertext encrypts 0 or 1
    /// This function will return a Vec of Ciphertext where at most one encryption of 1 is present
    /// The first encryption of one is kept
    fn only_keep_first_true<T>(&self, values: T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let num_ct_blocks = values.as_ref().d_blocks.lwe_ciphertext_count().0;
        if num_ct_blocks <= 1 {
            return values;
        }
        const ALREADY_SEEN: u64 = 2;
        let lut_fn = self.generate_lookup_table_bivariate(|current, previous| {
            if previous == 1 || previous == ALREADY_SEEN {
                ALREADY_SEEN
            } else {
                current
            }
        });

        let mut first_true: T = self.create_trivial_zero_radix(num_ct_blocks, streams);

        let mut clone_ct = values.duplicate(streams);
        self.compute_prefix_sum_hillis_steele(
            first_true.as_mut(),
            clone_ct.as_mut(),
            &lut_fn,
            0..num_ct_blocks,
            streams,
        );

        let lut = self.generate_lookup_table(|x| {
            let x = x % self.message_modulus.0;
            if x == ALREADY_SEEN {
                0
            } else {
                x
            }
        });

        let cloned_ct = first_true.duplicate(streams);
        self.apply_lookup_table(
            first_true.as_mut(),
            cloned_ct.as_ref(),
            &lut,
            0..num_ct_blocks,
            streams,
        );
        first_true
    }
}
