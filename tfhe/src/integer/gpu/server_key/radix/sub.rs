use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::CudaServerKey;

use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_sub_and_propagate_single_carry_assign,
    cuda_backend_unchecked_unsigned_overflowing_sub_assign, PBSType,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::shortint::parameters::LweBskGroupingFactor;

impl CudaServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg_1 = 12;
    /// let msg_2 = 10;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_sub(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.unchecked_sub_assign(&mut result, ct_right, streams);
        result
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, num_blocks, &streams);
    ///
    /// let msg_1 = 128;
    /// let msg_2 = 99;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// sks.unchecked_sub_assign(&mut d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct1.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        let neg = self.unchecked_neg(ct_right, streams);
        self.unchecked_add_assign(ct_left, &neg, streams);
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg_1 as u64);
    /// let ct2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.sub(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.sub_assign(&mut result, ct_right, streams);
        result
    }

    pub fn get_sub_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_sub_assign_size_on_gpu(ct_left, ct_right, streams)
    }

    pub fn sub_assign<T: CudaIntegerRadixCiphertext>(
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

        let _carry =
            self.sub_and_propagate_single_carry_assign(lhs, rhs, streams, None, OutputFlag::None);
    }

    pub fn get_sub_assign_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_add_assign_size_on_gpu(ct_left, ct_right, streams)
    }

    pub fn unsigned_overflowing_sub(
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
                tmp_rhs = ct_right.duplicate(stream);
                self.full_propagate_assign(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(stream);
                self.full_propagate_assign(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(stream);
                tmp_rhs = ct_right.duplicate(stream);

                self.full_propagate_assign(&mut tmp_lhs, stream);
                self.full_propagate_assign(&mut tmp_rhs, stream);

                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_unsigned_overflowing_sub(lhs, rhs, stream)
    }

    pub fn unchecked_unsigned_overflowing_sub(
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
        let mut ct_res = lhs.duplicate(stream);

        let compute_overflow = true;
        const INPUT_BORROW: Option<&CudaBooleanBlock> = None;

        let mut overflow_block: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(1, stream);
        let ciphertext = ct_res.as_mut();
        let uses_input_borrow = INPUT_BORROW.map_or(0u32, |_block| 1u32);

        let aux_block: CudaUnsignedRadixCiphertext = self.create_trivial_zero_radix(1, stream);
        let in_carry_dvec =
            INPUT_BORROW.map_or_else(|| aux_block.as_ref(), |block| block.as_ref().as_ref());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_unsigned_overflowing_sub_assign(
                        stream,
                        ciphertext,
                        rhs.as_ref(),
                        overflow_block.as_mut(),
                        in_carry_dvec,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_bsk.input_lwe_dimension(),
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        ciphertext.info.blocks.first().unwrap().message_modulus,
                        ciphertext.info.blocks.first().unwrap().carry_modulus,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        compute_overflow,
                        uses_input_borrow,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_unsigned_overflowing_sub_assign(
                        stream,
                        ciphertext,
                        rhs.as_ref(),
                        overflow_block.as_mut(),
                        in_carry_dvec,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        d_multibit_bsk.input_lwe_dimension(),
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        ciphertext.info.blocks.first().unwrap().message_modulus,
                        ciphertext.info.blocks.first().unwrap().carry_modulus,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        compute_overflow,
                        uses_input_borrow,
                        None,
                    );
                }
            }
        }
        let ct_overflowed = CudaBooleanBlock::from_cuda_radix_ciphertext(overflow_block.ciphertext);

        (ct_res, ct_overflowed)
    }

    pub(crate) fn sub_and_propagate_single_carry_assign<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
        streams: &CudaStreams,
        input_carry: Option<&CudaBooleanBlock>,
        requested_flag: OutputFlag,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut carry_out: T = self.create_trivial_zero_radix(1, streams);

        let num_blocks = lhs.as_mut().d_blocks.lwe_ciphertext_count().0 as u32;
        let uses_carry = input_carry.map_or(0u32, |_block| 1u32);
        let aux_block: T = self.create_trivial_zero_radix(1, streams);
        let in_carry: &CudaRadixCiphertext =
            input_carry.map_or_else(|| aux_block.as_ref(), |block| block.0.as_ref());

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_sub_and_propagate_single_carry_assign(
                        streams,
                        lhs.as_mut(),
                        rhs.as_ref(),
                        carry_out.as_mut(),
                        in_carry,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
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
                        requested_flag,
                        uses_carry,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_sub_and_propagate_single_carry_assign(
                        streams,
                        lhs.as_mut(),
                        rhs.as_ref(),
                        carry_out.as_mut(),
                        in_carry,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
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
                        requested_flag,
                        uses_carry,
                        None,
                    );
                }
            }
        }
        carry_out
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
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
    /// // Compute homomorphically an overflowing subtraction:
    /// let (d_ct_res, d_ct_overflowed) = sks.signed_overflowing_sub(&d_ct1, &d_ct2, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    /// let ct_overflowed = d_ct_overflowed.to_boolean_block(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i8 = cks.decrypt_signed(&ct_res);
    /// let dec_overflowed: bool = cks.decrypt_bool(&ct_overflowed);
    /// let (clear_result, clear_overflowed) = msg1.overflowing_sub(msg2);
    /// assert_eq!(dec_result, clear_result);
    /// assert_eq!(dec_overflowed, clear_overflowed);
    /// ```
    pub fn signed_overflowing_sub(
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
                tmp_rhs = ct_right.duplicate(stream);
                self.full_propagate_assign(&mut tmp_rhs, stream);

                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct_left.duplicate(stream);
                self.full_propagate_assign(&mut tmp_lhs, stream);
                (&tmp_lhs, ct_right)
            }
            (false, false) => {
                tmp_lhs = ct_left.duplicate(stream);
                tmp_rhs = ct_right.duplicate(stream);

                self.full_propagate_assign(&mut tmp_lhs, stream);
                self.full_propagate_assign(&mut tmp_rhs, stream);

                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_signed_overflowing_sub(lhs, rhs, stream)
    }

    pub fn unchecked_signed_overflowing_sub(
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
        let flipped_rhs = self.bitnot(ct_right, stream);
        let ct_input_carry: CudaUnsignedRadixCiphertext = self.create_trivial_radix(1, 1, stream);
        let input_carry = CudaBooleanBlock::from_cuda_radix_ciphertext(ct_input_carry.ciphertext);

        self.unchecked_signed_overflowing_add_with_input_carry(
            ct_left,
            &flipped_rhs,
            Some(&input_carry),
            stream,
        )
    }
}
