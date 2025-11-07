use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_boolean_bitnot_assign, cuda_backend_boolean_bitop_assign,
    cuda_backend_get_bitop_size_on_gpu, cuda_backend_get_boolean_bitnot_size_on_gpu,
    cuda_backend_get_boolean_bitop_size_on_gpu, cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_unchecked_bitnot_assign, cuda_backend_unchecked_bitop_assign, BitOpType,
    CudaServerKey, PBSType,
};

impl CudaServerKey {
    /// Computes homomorphically bitnot for an encrypted integer value.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitnot(&d_ct, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, !msg % 256);
    /// ```
    pub fn unchecked_bitnot<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct.duplicate(streams);
        self.unchecked_bitnot_assign(&mut result, streams);
        result
    }

    pub fn unchecked_bitnot_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) {
        unsafe {
            cuda_backend_unchecked_bitnot_assign(
                streams,
                ct.as_mut(),
                self.message_modulus,
                self.carry_modulus,
            );
        }
        ct.as_mut().info = ct.as_ref().info.after_bitnot();
    }

    /// Computes homomorphically boolean bitnot for an encrypted boolean value.
    ///
    ///
    /// The result is returned as a new boolean ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = true;
    ///
    /// let ct = cks.encrypt_bool(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaBooleanBlock::from_boolean_block(&ct, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.boolean_bitnot(&d_ct, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = CudaBooleanBlock::to_boolean_block(&d_ct_res, &streams);
    ///
    /// // Decrypt:
    /// let dec: bool = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec, !msg);
    /// ```
    pub fn boolean_bitnot(&self, ct: &CudaBooleanBlock, streams: &CudaStreams) -> CudaBooleanBlock {
        let mut result = ct.duplicate(streams);
        self.boolean_bitnot_assign(&mut result, streams);
        result
    }

    pub fn boolean_bitnot_assign(&self, ct: &mut CudaBooleanBlock, streams: &CudaStreams) {
        self.boolean_bitnot_assign_executor(ct, false, streams);
    }

    /// Computes homomorphically boolean bitand for an encrypted boolean value.
    ///
    ///
    /// The result is returned as a new boolean ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = true;
    /// let msg2 = false;
    ///
    /// let ct1 = cks.encrypt_bool(msg1);
    /// let ct2 = cks.encrypt_bool(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaBooleanBlock::from_boolean_block(&ct1, &streams);
    /// let d_ct2 = CudaBooleanBlock::from_boolean_block(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.boolean_bitand(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = CudaBooleanBlock::to_boolean_block(&d_ct_res, &streams);
    /// let expected = msg1 & msg2;
    ///
    /// // Decrypt:
    /// let dec: bool = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec, expected);
    /// ```
    pub fn boolean_bitand(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock {
        let mut result = ct_left.duplicate(streams);
        self.boolean_bitand_assign(&mut result, ct_right, streams);
        result
    }

    pub fn boolean_bitand_assign(
        &self,
        ct_left: &mut CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) {
        self.boolean_bitop_assign_executor(ct_left, ct_right, BitOpType::And, false, streams);
    }

    /// Computes homomorphically boolean bitor for an encrypted boolean value.
    ///
    ///
    /// The result is returned as a new boolean ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = true;
    /// let msg2 = false;
    ///
    /// let ct1 = cks.encrypt_bool(msg1);
    /// let ct2 = cks.encrypt_bool(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaBooleanBlock::from_boolean_block(&ct1, &streams);
    /// let d_ct2 = CudaBooleanBlock::from_boolean_block(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise or:
    /// let d_ct_res = sks.boolean_bitor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = CudaBooleanBlock::to_boolean_block(&d_ct_res, &streams);
    /// let expected = msg1 | msg2;
    ///
    /// // Decrypt:
    /// let dec: bool = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec, expected);
    /// ```
    pub fn boolean_bitor(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock {
        let mut result = ct_left.duplicate(streams);
        self.boolean_bitor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn boolean_bitor_assign(
        &self,
        ct_left: &mut CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) {
        self.boolean_bitop_assign_executor(ct_left, ct_right, BitOpType::Or, false, streams);
    }

    /// Computes homomorphically boolean bitxor for an encrypted boolean value.
    ///
    ///
    /// The result is returned as a new boolean ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = true;
    /// let msg2 = false;
    ///
    /// let ct1 = cks.encrypt_bool(msg1);
    /// let ct2 = cks.encrypt_bool(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaBooleanBlock::from_boolean_block(&ct1, &streams);
    /// let d_ct2 = CudaBooleanBlock::from_boolean_block(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise xor:
    /// let d_ct_res = sks.boolean_bitxor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = CudaBooleanBlock::to_boolean_block(&d_ct_res, &streams);
    /// let expected = msg1 ^ msg2;
    ///
    /// // Decrypt:
    /// let dec: bool = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec, expected);
    /// ```
    pub fn boolean_bitxor(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock {
        let mut result = ct_left.duplicate(streams);
        self.boolean_bitxor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn boolean_bitxor_assign(
        &self,
        ct_left: &mut CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) {
        self.boolean_bitop_assign_executor(ct_left, ct_right, BitOpType::Xor, false, streams);
    }

    pub fn boolean_bitop_assign_executor(
        &self,
        ct_left: &mut CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        op: BitOpType,
        is_unchecked: bool,
        streams: &CudaStreams,
    ) {
        assert_eq!(
            ct_left.0.as_ref().d_blocks.lwe_dimension(),
            ct_right.0.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.0.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.0.as_ref().d_blocks.lwe_ciphertext_count()
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_boolean_bitop_assign(
                        streams,
                        ct_left.0.as_mut(),
                        ct_right.0.as_ref(),
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
                        op,
                        is_unchecked,
                        1u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_boolean_bitop_assign(
                        streams,
                        ct_left.0.as_mut(),
                        ct_right.0.as_ref(),
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
                        op,
                        is_unchecked,
                        1u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn unchecked_boolean_bitnot(
        &self,
        ct: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> CudaBooleanBlock {
        let mut result = ct.duplicate(streams);
        self.unchecked_boolean_bitnot_assign(&mut result, streams);
        result
    }

    pub fn unchecked_boolean_bitnot_assign(
        &self,
        ct: &mut CudaBooleanBlock,
        streams: &CudaStreams,
    ) {
        self.boolean_bitnot_assign_executor(ct, true, streams);
    }

    fn boolean_bitnot_assign_executor(
        &self,
        ct: &mut CudaBooleanBlock,
        is_unchecked: bool,
        streams: &CudaStreams,
    ) {
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_boolean_bitnot_assign(
                        streams,
                        &mut ct.0.ciphertext as &mut CudaRadixCiphertext,
                        is_unchecked,
                        &d_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        d_bsk.output_lwe_dimension(),
                        d_bsk.input_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_bsk.decomp_level_count(),
                        d_bsk.decomp_base_log(),
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_boolean_bitnot_assign(
                        streams,
                        &mut ct.0.ciphertext as &mut CudaRadixCiphertext,
                        is_unchecked,
                        &d_multibit_bsk.d_vec,
                        &self.key_switching_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        d_multibit_bsk.output_lwe_dimension(),
                        d_multibit_bsk.input_lwe_dimension(),
                        self.key_switching_key.decomposition_level_count(),
                        self.key_switching_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count(),
                        d_multibit_bsk.decomp_base_log(),
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    /// Computes homomorphically bitand between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitand(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn unchecked_bitand<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.unchecked_bitand_assign(&mut result, ct_right, streams);
        result
    }

    pub(crate) fn unchecked_bitop_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        op: BitOpType,
        streams: &CudaStreams,
    ) {
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_dimension(),
            ct_right.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.as_ref().d_blocks.lwe_ciphertext_count()
        );

        let lwe_ciphertext_count = ct_left.as_ref().d_blocks.lwe_ciphertext_count();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_bitop_assign(
                        streams,
                        ct_left.as_mut(),
                        ct_right.as_ref(),
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
                        op,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_bitop_assign(
                        streams,
                        ct_left.as_mut(),
                        ct_right.as_ref(),
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
                        op,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn get_boolean_bitop_size_on_gpu(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        op: BitOpType,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            ct_left.0.as_ref().d_blocks.lwe_dimension(),
            ct_right.0.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            ct_left.0.as_ref().d_blocks.lwe_ciphertext_count(),
            ct_right.0.as_ref().d_blocks.lwe_ciphertext_count()
        );
        let boolean_bitop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_boolean_bitop_size_on_gpu(
                streams,
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
                op,
                false,
                1u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_boolean_bitop_size_on_gpu(
                    streams,
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
                    op,
                    false,
                    1u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        boolean_bitop_mem
    }

    pub fn get_bitop_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        op: BitOpType,
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

        let bitop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_bitop_size_on_gpu(
                streams,
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
                op,
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => cuda_backend_get_bitop_size_on_gpu(
                streams,
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
                op,
                lwe_ciphertext_count.0 as u32,
                PBSType::MultiBit,
                d_multibit_bsk.grouping_factor,
                None,
            ),
        };
        actual_full_prop_mem.max(bitop_mem)
    }

    pub fn unchecked_bitand_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        self.unchecked_bitop_assign(ct_left, ct_right, BitOpType::And, streams);
    }

    /// Computes homomorphically bitor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 200u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn unchecked_bitor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.unchecked_bitor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn unchecked_bitor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        self.unchecked_bitop_assign(ct_left, ct_right, BitOpType::Or, streams);
    }

    /// Computes homomorphically bitxor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 49;
    /// let msg2 = 64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitxor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 ^ msg2);
    /// ```
    pub fn unchecked_bitxor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.unchecked_bitxor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn unchecked_bitxor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        self.unchecked_bitop_assign(ct_left, ct_right, BitOpType::Xor, streams);
    }

    /// Computes homomorphically bitand between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitand(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn bitand<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.bitand_assign(&mut result, ct_right, streams);
        result
    }

    pub fn bitand_assign<T: CudaIntegerRadixCiphertext>(
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
        self.unchecked_bitop_assign(lhs, rhs, BitOpType::And, streams);
    }

    /// Computes homomorphically bitor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn bitor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.bitor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn bitor_assign<T: CudaIntegerRadixCiphertext>(
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

        self.unchecked_bitop_assign(lhs, rhs, BitOpType::Or, streams);
    }

    /// Computes homomorphically bitxor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitxor(&d_ct1, &d_ct2, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 ^ msg2);
    /// ```
    pub fn bitxor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> T {
        let mut result = ct_left.duplicate(streams);
        self.bitxor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn bitxor_assign<T: CudaIntegerRadixCiphertext>(
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

        self.unchecked_bitop_assign(lhs, rhs, BitOpType::Xor, streams);
    }

    /// Computes homomorphically bitnot for an encrypted integer value.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitnot(&d_ct, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, !msg % 256);
    /// ```
    pub fn bitnot<T: CudaIntegerRadixCiphertext>(&self, ct: &T, streams: &CudaStreams) -> T {
        let mut result = ct.duplicate(streams);
        self.bitnot_assign(&mut result, streams);
        result
    }

    pub fn bitnot_assign<T: CudaIntegerRadixCiphertext>(&self, ct: &mut T, streams: &CudaStreams) {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_bitnot_assign(ct, streams);
    }

    pub fn get_boolean_bitand_size_on_gpu(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_boolean_bitop_size_on_gpu(ct_left, ct_right, BitOpType::And, streams)
    }

    pub fn get_boolean_bitor_size_on_gpu(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_boolean_bitop_size_on_gpu(ct_left, ct_right, BitOpType::Or, streams)
    }

    pub fn get_boolean_bitxor_size_on_gpu(
        &self,
        ct_left: &CudaBooleanBlock,
        ct_right: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_boolean_bitop_size_on_gpu(ct_left, ct_right, BitOpType::Xor, streams)
    }

    pub fn get_bitand_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_bitop_size_on_gpu(ct_left, ct_right, BitOpType::And, streams)
    }

    pub fn get_bitor_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_bitop_size_on_gpu(ct_left, ct_right, BitOpType::Or, streams)
    }

    pub fn get_bitxor_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_bitop_size_on_gpu(ct_left, ct_right, BitOpType::Xor, streams)
    }

    pub fn get_boolean_bitnot_size_on_gpu(
        &self,
        _ct: &CudaBooleanBlock,
        streams: &CudaStreams,
    ) -> u64 {
        let boolean_bitnot_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_boolean_bitnot_size_on_gpu(
                streams,
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
                false,
                1u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_boolean_bitnot_size_on_gpu(
                    streams,
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
                    false,
                    1u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };

        boolean_bitnot_mem
    }

    pub fn get_bitnot_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        streams: &CudaStreams,
    ) -> u64 {
        let full_prop_mem = if ct.block_carries_are_empty() {
            0
        } else {
            match &self.bootstrapping_key {
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
            }
        };

        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let bitnot_mem = (lwe_ciphertext_count.0 * size_of::<u64>()) as u64;
        full_prop_mem.max(bitnot_mem)
    }
}
