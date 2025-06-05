use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    get_add_and_propagate_single_carry_assign_async_size_on_gpu,
    get_full_propagate_assign_size_on_gpu, unchecked_add_integer_radix_assign_async,
    unchecked_partial_sum_ciphertexts_integer_radix_kb_assign_async, PBSType,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::shortint::ciphertext::NoiseLevel;

impl CudaServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
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
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
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
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.add(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.add_assign(&mut result, ct_right, streams);
        result
    }

    pub fn get_add_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_add_assign_size_on_gpu(ct_left, ct_right, streams)
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn add_assign_async<T: CudaIntegerRadixCiphertext>(
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
                tmp_rhs = ct_right.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_assign_async(ct_left, streams);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.duplicate_async(streams);

                self.full_propagate_assign_async(ct_left, streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct_left, &tmp_rhs)
            }
        };

        let _carry = self.add_and_propagate_single_carry_assign_async(
            lhs,
            rhs,
            streams,
            None,
            OutputFlag::None,
        );
    }

    pub fn add_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.add_assign_async(ct_left, ct_right, streams);
        }
        streams.synchronize();
    }

    pub fn get_add_assign_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count().0,
            ct_right.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        let full_prop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_full_propagate_assign_size_on_gpu(
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
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_full_propagate_assign_size_on_gpu(
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

        let num_blocks = ct_left.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let add_assign_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                get_add_and_propagate_single_carry_assign_async_size_on_gpu(
                    streams,
                    d_bsk.input_lwe_dimension(),
                    d_bsk.glwe_dimension(),
                    d_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count(),
                    d_bsk.decomp_base_log(),
                    num_blocks,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    OutputFlag::None,
                    0u32,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_add_and_propagate_single_carry_assign_async_size_on_gpu(
                    streams,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    num_blocks,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    OutputFlag::None,
                    0u32,
                    None,
                )
            }
        };
        actual_full_prop_mem.max(add_assign_mem)
    }

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
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg1 = 10;
    /// let msg2 = 127;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_add(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn unchecked_add<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.unchecked_add_assign(&mut result, ct_right, streams);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_add_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        let ciphertext_left = ct_left.as_mut();
        let ciphertext_right = ct_right.as_ref();
        assert_eq!(
            ciphertext_left.d_blocks.lwe_dimension(),
            ciphertext_right.d_blocks.lwe_dimension(),
            "Mismatched lwe dimension between ct_left ({:?}) and ct_right ({:?})",
            ciphertext_left.d_blocks.lwe_dimension(),
            ciphertext_right.d_blocks.lwe_dimension()
        );

        assert_eq!(
            ciphertext_left.d_blocks.ciphertext_modulus(),
            ciphertext_right.d_blocks.ciphertext_modulus(),
            "Mismatched moduli between ct_left ({:?}) and ct_right ({:?})",
            ciphertext_left.d_blocks.ciphertext_modulus(),
            ciphertext_right.d_blocks.ciphertext_modulus()
        );

        unsafe {
            unchecked_add_integer_radix_assign_async(streams, ciphertext_left, ciphertext_right);
        }
    }

    pub fn unchecked_add_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unchecked_add_assign_async(ct_left, ct_right, streams);
        }
        streams.synchronize();
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_partial_sum_ciphertexts_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        result: &mut T,
        ciphertexts: &[T],
        reduce_degrees_for_single_carry_propagation: bool,
        streams: &CudaStreams,
    ) {
        if ciphertexts.is_empty() {
            return;
        }

        result.as_mut().d_blocks.0.d_vec.copy_from_gpu_async(
            &ciphertexts[0].as_ref().d_blocks.0.d_vec,
            streams,
            0,
        );
        result.as_mut().info = ciphertexts[0].as_ref().info.clone();
        if ciphertexts.len() == 1 {
            return;
        }

        let num_blocks = ciphertexts[0].as_ref().d_blocks.0.lwe_ciphertext_count;

        assert!(
            ciphertexts[1..]
                .iter()
                .all(|ct| ct.as_ref().d_blocks.0.lwe_ciphertext_count == num_blocks),
            "Not all ciphertexts have the same number of blocks"
        );

        if ciphertexts.len() == 2 {
            self.add_assign_async(result, &ciphertexts[1], streams);
            return;
        }

        let radix_count_in_vec = ciphertexts.len();

        let mut terms = CudaRadixCiphertext::from_radix_ciphertext_vec(ciphertexts, streams);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_partial_sum_ciphertexts_integer_radix_kb_assign_async(
                    streams,
                    result.as_mut(),
                    &mut terms,
                    reduce_degrees_for_single_carry_propagation,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    num_blocks.0 as u32,
                    radix_count_in_vec as u32,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_partial_sum_ciphertexts_integer_radix_kb_assign_async(
                    streams,
                    result.as_mut(),
                    &mut terms,
                    reduce_degrees_for_single_carry_propagation,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    num_blocks.0 as u32,
                    radix_count_in_vec as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                );
            }
        }
    }

    pub fn unchecked_sum_ciphertexts<T: CudaIntegerRadixCiphertext>(
        &self,
        ciphertexts: &[T],
        streams: &CudaStreams,
    ) -> T {
        let result = unsafe { self.unchecked_sum_ciphertexts_async(ciphertexts, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_sum_ciphertexts_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ciphertexts: &[T],
        streams: &CudaStreams,
    ) -> T {
        let mut result = self
            .unchecked_partial_sum_ciphertexts_async(ciphertexts, true, streams)
            .unwrap();

        self.propagate_single_carry_assign_async(&mut result, streams, None, OutputFlag::None);
        assert!(result.block_carries_are_empty());
        result
    }

    pub fn unchecked_partial_sum_ciphertexts<T: CudaIntegerRadixCiphertext>(
        &self,
        ciphertexts: &[T],
        streams: &CudaStreams,
    ) -> Option<T> {
        let result =
            unsafe { self.unchecked_partial_sum_ciphertexts_async(ciphertexts, false, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_partial_sum_ciphertexts_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ciphertexts: &[T],
        reduce_degrees_for_single_carry_propagation: bool,
        streams: &CudaStreams,
    ) -> Option<T> {
        if ciphertexts.is_empty() {
            return None;
        }

        let mut result = unsafe { ciphertexts[0].duplicate_async(streams) };

        if ciphertexts.len() == 1 {
            streams.synchronize();
            return Some(result);
        }

        self.unchecked_partial_sum_ciphertexts_assign_async(
            &mut result,
            ciphertexts,
            reduce_degrees_for_single_carry_propagation,
            streams,
        );

        Some(result)
    }

    pub fn sum_ciphertexts<T: CudaIntegerRadixCiphertext>(
        &self,
        ciphertexts: Vec<T>,
        streams: &CudaStreams,
    ) -> Option<T> {
        let res = unsafe { self.sum_ciphertexts_async(ciphertexts, streams) };
        streams.synchronize();
        res
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn sum_ciphertexts_async<T: CudaIntegerRadixCiphertext>(
        &self,
        mut ciphertexts: Vec<T>,
        streams: &CudaStreams,
    ) -> Option<T> {
        if ciphertexts.is_empty() {
            return None;
        }

        ciphertexts
            .iter_mut()
            .filter(|ct| !ct.block_carries_are_empty())
            .for_each(|ct| {
                self.full_propagate_assign_async(&mut *ct, streams);
            });

        Some(self.unchecked_sum_ciphertexts_async(&ciphertexts, streams))
    }

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
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    /// let total_bits = num_blocks * cks.parameters().message_modulus().0.ilog2() as usize;
    /// let modulus = 1 << total_bits;
    ///
    /// let msg1 = 127;
    /// let msg2 = 130;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically an overflowing addition:
    /// let (d_ct_res, d_ct_overflowed) = sks.unsigned_overflowing_add(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let ct_overflowed = d_ct_overflowed.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// let dec_overflowed: bool = cks.decrypt_bool(&ct_overflowed);
    /// assert_eq!(dec_result, (msg1 + msg2) % modulus);
    /// assert!(dec_overflowed);
    /// ```
    pub fn unsigned_overflowing_add(
        &self,
        ct_left: &CudaUnsignedRadixCiphertext,
        ct_right: &CudaUnsignedRadixCiphertext,
        stream: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                unsafe {
                    tmp_rhs = ct_right.duplicate_async(stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                }
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                unsafe {
                    tmp_lhs = ct_left.duplicate_async(stream);
                    self.full_propagate_assign_async(&mut tmp_lhs, stream);
                }
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                unsafe {
                    tmp_lhs = ct_left.duplicate_async(stream);
                    tmp_rhs = ct_right.duplicate_async(stream);

                    self.full_propagate_assign_async(&mut tmp_lhs, stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                }

                (&tmp_lhs, &tmp_rhs)
            }
        };
        self.unchecked_unsigned_overflowing_add(lhs, rhs, stream)
    }

    pub fn unchecked_unsigned_overflowing_add(
        &self,
        lhs: &CudaUnsignedRadixCiphertext,
        rhs: &CudaUnsignedRadixCiphertext,
        stream: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock) {
        assert_eq!(
            lhs.as_ref().d_blocks.lwe_ciphertext_count(),
            rhs.as_ref().d_blocks.lwe_ciphertext_count(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.as_ref().d_blocks.lwe_ciphertext_count().0,
            rhs.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        let ct_res;
        let ct_overflowed;
        unsafe {
            (ct_res, ct_overflowed) =
                self.unchecked_unsigned_overflowing_add_async(lhs, rhs, stream);
        }
        stream.synchronize();

        (ct_res, ct_overflowed)
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_unsigned_overflowing_add_async(
        &self,
        lhs: &CudaUnsignedRadixCiphertext,
        rhs: &CudaUnsignedRadixCiphertext,
        stream: &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock) {
        let output_flag = OutputFlag::from_signedness(CudaUnsignedRadixCiphertext::IS_SIGNED);

        let mut ct_res = lhs.duplicate_async(stream);
        let mut carry_out: CudaUnsignedRadixCiphertext = self
            .add_and_propagate_single_carry_assign_async(
                &mut ct_res,
                rhs,
                stream,
                None,
                output_flag,
            );

        if lhs.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO
            && rhs.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO
        {
            carry_out.as_mut().info = carry_out.as_ref().info.boolean_info(NoiseLevel::ZERO);
        } else {
            carry_out.as_mut().info = carry_out.as_ref().info.boolean_info(NoiseLevel::NOMINAL);
        }

        let ct_overflowed = CudaBooleanBlock::from_cuda_radix_ciphertext(carry_out.ciphertext);

        (ct_res, ct_overflowed)
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_signed_overflowing_add_async(
        &self,
        lhs: &CudaSignedRadixCiphertext,
        rhs: &CudaSignedRadixCiphertext,
        input_carry: Option<&CudaBooleanBlock>,
        stream: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock) {
        let output_flag = OutputFlag::from_signedness(CudaSignedRadixCiphertext::IS_SIGNED);

        let mut ct_res = lhs.duplicate_async(stream);
        let carry_out: CudaSignedRadixCiphertext = self
            .add_and_propagate_single_carry_assign_async(
                &mut ct_res,
                rhs,
                stream,
                input_carry,
                output_flag,
            );

        let ct_overflowed = CudaBooleanBlock::from_cuda_radix_ciphertext(carry_out.ciphertext);

        (ct_res, ct_overflowed)
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    /// let total_bits = num_blocks * cks.parameters().message_modulus().0.ilog2() as usize;
    /// let modulus = 1 << total_bits;
    ///
    /// let msg1: i8 = 120;
    /// let msg2: i8 = 8;
    ///
    /// let ct1 = cks.encrypt_signed(msg1);
    /// let ct2 = cks.encrypt_signed(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically an overflowing addition:
    /// let (d_ct_res, d_ct_overflowed) = sks.signed_overflowing_add(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    /// let ct_overflowed = d_ct_overflowed.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i8 = cks.decrypt_signed(&ct_res);
    /// let dec_overflowed: bool = cks.decrypt_bool(&ct_overflowed);
    /// let (clear_result, clear_overflowed) = msg1.overflowing_add(msg2);
    /// assert_eq!(dec_result, clear_result);
    /// assert_eq!(dec_overflowed, clear_overflowed);
    /// ```
    pub fn signed_overflowing_add(
        &self,
        ct_left: &CudaSignedRadixCiphertext,
        ct_right: &CudaSignedRadixCiphertext,
        stream: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                unsafe {
                    tmp_rhs = ct_right.duplicate_async(stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                }
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                unsafe {
                    tmp_lhs = ct_left.duplicate_async(stream);
                    self.full_propagate_assign_async(&mut tmp_lhs, stream);
                }
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                unsafe {
                    tmp_lhs = ct_left.duplicate_async(stream);
                    tmp_rhs = ct_right.duplicate_async(stream);

                    self.full_propagate_assign_async(&mut tmp_lhs, stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                }

                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_signed_overflowing_add(lhs, rhs, stream)
    }

    pub fn unchecked_signed_overflowing_add(
        &self,
        ct_left: &CudaSignedRadixCiphertext,
        ct_right: &CudaSignedRadixCiphertext,
        stream: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock) {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count().0,
            ct_right.as_ref().d_blocks.lwe_ciphertext_count().0,
            "lhs and rhs must have the name number of blocks ({} vs {})",
            ct_left.as_ref().d_blocks.lwe_ciphertext_count().0,
            ct_right.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        assert!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count().0 > 0,
            "inputs cannot be empty"
        );

        let result;
        let overflowed;
        unsafe {
            (result, overflowed) =
                self.unchecked_signed_overflowing_add_async(ct_left, ct_right, None, stream);
        };
        stream.synchronize();
        (result, overflowed)
    }
}
