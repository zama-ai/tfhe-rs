use crate::core_crypto::gpu::algorithms::{
    cuda_lwe_ciphertext_negate_assign, cuda_lwe_ciphertext_plaintext_add_assign,
};
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    unchecked_bitop_integer_radix_kb_assign_async, BitOpType, CudaServerKey, PBSType,
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
    /// use std::ops::Not;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitnot(&d_ct, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct.duplicate_async(streams) };
        self.unchecked_bitnot_assign(&mut result, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_bitnot_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) {
        // We do (-ciphertext) + (msg_mod -1) as it allows to avoid an allocation
        cuda_lwe_ciphertext_negate_assign(&mut ct.as_mut().d_blocks, streams);

        let ct_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        let scalar = self.message_modulus.0 as u8 - 1;
        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;
        let shift_plaintext = u64::from(scalar) * delta;

        let scalar_vector = vec![shift_plaintext; ct_blocks];
        let mut d_decomposed_scalar = CudaVec::<u64>::new_async(
            ct.as_ref().d_blocks.lwe_ciphertext_count().0,
            streams,
            streams.gpu_indexes[0],
        );
        d_decomposed_scalar.copy_from_cpu_async(
            scalar_vector.as_slice(),
            streams,
            streams.gpu_indexes[0],
        );

        cuda_lwe_ciphertext_plaintext_add_assign(
            &mut ct.as_mut().d_blocks,
            &d_decomposed_scalar,
            streams,
        );
        ct.as_mut().info = ct.as_ref().info.after_bitnot();
    }

    pub fn unchecked_bitnot_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unchecked_bitnot_assign_async(ct, streams);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitand(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.unchecked_bitand_assign(&mut result, ct_right, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_bitop_assign_async<T: CudaIntegerRadixCiphertext>(
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

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_bitop_integer_radix_kb_assign_async(
                    streams,
                    &mut ct_left.as_mut().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_bitop_integer_radix_kb_assign_async(
                    streams,
                    &mut ct_left.as_mut().d_blocks.0.d_vec,
                    &ct_right.as_ref().d_blocks.0.d_vec,
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
                );
            }
        }
    }

    pub fn unchecked_bitand_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::And, streams);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitand(&ct_right.as_ref().info);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 200u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitor(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.unchecked_bitor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn unchecked_bitor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::Or, streams);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitor(&ct_right.as_ref().info);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 49;
    /// let msg2 = 64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitxor(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.unchecked_bitxor_assign(&mut result, ct_right, streams);
        result
    }

    pub fn unchecked_bitxor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::Xor, streams);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitxor(&ct_right.as_ref().info);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitand(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.bitand_assign(&mut result, ct_right, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn bitand_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        let mut tmp_rhs;

        let (lhs, rhs) = unsafe {
            match (
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
            }
        };
        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::And, streams);
    }

    pub fn bitand_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.bitand_assign_async(ct_left, ct_right, streams);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitor(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.bitor_assign(&mut result, ct_right, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn bitor_assign_async<T: CudaIntegerRadixCiphertext>(
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

        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::Or, streams);
    }

    pub fn bitor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.bitor_assign_async(ct_left, ct_right, streams);
        }
        streams.synchronize();
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
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut streams);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitxor(&d_ct1, &d_ct2, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
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
        let mut result = unsafe { ct_left.duplicate_async(streams) };
        self.bitxor_assign(&mut result, ct_right, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn bitxor_assign_async<T: CudaIntegerRadixCiphertext>(
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

        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::Xor, streams);
    }

    pub fn bitxor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        streams: &CudaStreams,
    ) {
        unsafe {
            self.bitxor_assign_async(ct_left, ct_right, streams);
        }
        streams.synchronize();
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
    /// use std::ops::Not;
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut streams);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut streams);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitnot(&d_ct, &mut streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut streams);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, !msg % 256);
    /// ```
    pub fn bitnot<T: CudaIntegerRadixCiphertext>(&self, ct: &T, streams: &CudaStreams) -> T {
        let mut result = unsafe { ct.duplicate_async(streams) };
        self.bitnot_assign(&mut result, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn bitnot_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        streams: &CudaStreams,
    ) {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, streams);
        }

        self.unchecked_bitnot_assign_async(ct, streams);
    }

    pub fn bitnot_assign<T: CudaIntegerRadixCiphertext>(&self, ct: &mut T, streams: &CudaStreams) {
        unsafe {
            self.bitnot_assign_async(ct, streams);
        }
        streams.synchronize();
    }
}
