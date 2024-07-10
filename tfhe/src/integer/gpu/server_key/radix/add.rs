use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    unchecked_add_integer_radix_assign_async,
    unchecked_signed_overflowing_add_or_sub_radix_kb_assign_async,
    unchecked_sum_ciphertexts_integer_radix_kb_assign_async, PBSType,
};
use crate::integer::server_key::radix_parallel::sub::SignedOperation;
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
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &streams);
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
        self.unchecked_add_assign_async(lhs, rhs, streams);
        let _carry = self.propagate_single_carry_assign_async(lhs, streams);
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

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &streams);
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

        let lwe_dimension = ciphertext_left.d_blocks.lwe_dimension();
        let lwe_ciphertext_count = ciphertext_left.d_blocks.lwe_ciphertext_count();

        unchecked_add_integer_radix_assign_async(
            streams,
            &mut ciphertext_left.d_blocks.0.d_vec,
            &ciphertext_right.d_blocks.0.d_vec,
            lwe_dimension,
            lwe_ciphertext_count.0 as u32,
        );

        ciphertext_left.info = ciphertext_left.info.after_add(&ciphertext_right.info);
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
    pub unsafe fn unchecked_sum_ciphertexts_assign_async(
        &self,
        result: &mut CudaUnsignedRadixCiphertext,
        ciphertexts: &[CudaUnsignedRadixCiphertext],
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

        let mut terms = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            ciphertexts
                .iter()
                .map(|ciphertext| &ciphertext.as_ref().d_blocks),
            streams,
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_sum_ciphertexts_integer_radix_kb_assign_async(
                    streams,
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &mut terms.0.d_vec,
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_sum_ciphertexts_integer_radix_kb_assign_async(
                    streams,
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &mut terms.0.d_vec,
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
                );
            }
        }
    }

    pub fn unchecked_sum_ciphertexts(
        &self,
        ciphertexts: &[CudaUnsignedRadixCiphertext],
        streams: &CudaStreams,
    ) -> Option<CudaUnsignedRadixCiphertext> {
        if ciphertexts.is_empty() {
            return None;
        }

        let mut result = unsafe { ciphertexts[0].duplicate_async(streams) };

        if ciphertexts.len() == 1 {
            return Some(result);
        }

        unsafe { self.unchecked_sum_ciphertexts_assign_async(&mut result, ciphertexts, streams) };
        streams.synchronize();
        Some(result)
    }

    pub fn sum_ciphertexts(
        &self,
        mut ciphertexts: Vec<CudaUnsignedRadixCiphertext>,
        streams: &CudaStreams,
    ) -> Option<CudaUnsignedRadixCiphertext> {
        if ciphertexts.is_empty() {
            return None;
        }

        unsafe {
            ciphertexts
                .iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| {
                    self.full_propagate_assign_async(&mut *ct, streams);
                });
        }

        self.unchecked_sum_ciphertexts(&ciphertexts, streams)
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &streams);
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
        let mut ct_res = self.unchecked_add(lhs, rhs, stream);
        let mut carry_out = self.propagate_single_carry_assign_async(&mut ct_res, stream);

        ct_res.as_mut().info = ct_res
            .as_ref()
            .info
            .after_overflowing_add(&rhs.as_ref().info);

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

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &streams);
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

        self.unchecked_signed_overflowing_add_or_sub(
            ct_left,
            ct_right,
            SignedOperation::Addition,
            stream,
        )
    }

    pub(crate) fn unchecked_signed_overflowing_add_or_sub(
        &self,
        lhs: &CudaSignedRadixCiphertext,
        rhs: &CudaSignedRadixCiphertext,
        signed_operation: SignedOperation,
        streams: &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock) {
        assert!(self.message_modulus.0 >= 4 && self.carry_modulus.0 >= 4);

        let mut result: CudaSignedRadixCiphertext;
        unsafe {
            result = lhs.duplicate_async(streams);
        }
        let carry_out: CudaSignedRadixCiphertext = self.create_trivial_zero_radix(1, streams);
        let mut overflowed = CudaBooleanBlock::from_cuda_radix_ciphertext(carry_out.ciphertext);

        unsafe {
            self.unchecked_signed_overflowing_add_or_sub_assign_async(
                &mut result,
                rhs,
                &mut overflowed,
                signed_operation,
                streams,
            );
            streams.synchronize();
        }

        (result, overflowed)
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronized
    pub(crate) unsafe fn unchecked_signed_overflowing_add_or_sub_assign_async(
        &self,
        lhs: &mut CudaSignedRadixCiphertext,
        rhs: &CudaSignedRadixCiphertext,
        overflowed: &mut CudaBooleanBlock,
        signed_operation: SignedOperation,
        streams: &CudaStreams,
    ) {
        if lhs.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO
            && rhs.as_ref().info.blocks.last().unwrap().noise_level == NoiseLevel::ZERO
        {
            overflowed.as_mut().ciphertext.info = overflowed
                .as_ref()
                .ciphertext
                .info
                .boolean_info(NoiseLevel::ZERO);
        } else {
            overflowed.as_mut().ciphertext.info = overflowed
                .as_ref()
                .ciphertext
                .info
                .boolean_info(NoiseLevel::NOMINAL);
        }
        let num_blocks = lhs.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        let signed_operation_numeric: i8 =
            if matches!(signed_operation, SignedOperation::Subtraction) {
                -1
            } else {
                1
            };
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_overflowing_add_or_sub_radix_kb_assign_async(
                    streams,
                    &mut lhs.as_mut().d_blocks.0.d_vec,
                    &rhs.as_ref().d_blocks.0.d_vec,
                    &mut overflowed.as_mut().ciphertext.d_blocks.0.d_vec,
                    signed_operation_numeric,
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
                    num_blocks,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_overflowing_add_or_sub_radix_kb_assign_async(
                    streams,
                    &mut lhs.as_mut().d_blocks.0.d_vec,
                    &rhs.as_ref().d_blocks.0.d_vec,
                    &mut overflowed.as_mut().ciphertext.d_blocks.0.d_vec,
                    signed_operation_numeric,
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
                    num_blocks,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        };

        lhs.as_mut().info = lhs
            .as_ref()
            .info
            .after_overflowing_add(&rhs.ciphertext.info);
    }
}
