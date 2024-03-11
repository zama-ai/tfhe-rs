use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{BitOpType, CudaServerKey};

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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitnot(&d_ct, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, !msg % 256);
    /// ```
    pub fn unchecked_bitnot<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_bitnot_assign(&mut result, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_bitnot_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        stream: &CudaStream,
    ) {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_bitnot_integer_radix_classic_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
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
                    lwe_ciphertext_count.0 as u32,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_bitnot_integer_radix_multibit_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
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
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }
    }

    pub fn unchecked_bitnot_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_bitnot_assign_async(ct, stream);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitand(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn unchecked_bitand<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_bitand_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_bitop_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        op: BitOpType,
        stream: &CudaStream,
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
                stream.unchecked_bitop_integer_radix_classic_kb_assign_async(
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_bitop_integer_radix_multibit_kb_assign_async(
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
                    d_multibit_bsk.grouping_factor,
                    op,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }
    }

    pub fn unchecked_bitand_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::And, stream);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitand(&ct_right.as_ref().info);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 200u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitor(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn unchecked_bitor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_bitor_assign(&mut result, ct_right, stream);
        result
    }

    pub fn unchecked_bitor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::Or, stream);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitor(&ct_right.as_ref().info);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 49;
    /// let msg2 = 64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.unchecked_bitxor(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 ^ msg2);
    /// ```
    pub fn unchecked_bitxor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_bitxor_assign(&mut result, ct_right, stream);
        result
    }

    pub fn unchecked_bitxor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_bitop_assign_async(ct_left, ct_right, BitOpType::Xor, stream);
            ct_left.as_mut().info = ct_left.as_ref().info.after_bitxor(&ct_right.as_ref().info);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitand(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn bitand<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.bitand_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn bitand_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        let mut tmp_rhs;

        let (lhs, rhs) = unsafe {
            match (
                ct_left.block_carries_are_empty(),
                ct_right.block_carries_are_empty(),
            ) {
                (true, true) => (ct_left, ct_right),
                (true, false) => {
                    tmp_rhs = ct_right.duplicate_async(stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                    (ct_left, &tmp_rhs)
                }
                (false, true) => {
                    self.full_propagate_assign_async(ct_left, stream);
                    (ct_left, ct_right)
                }
                (false, false) => {
                    tmp_rhs = ct_right.duplicate_async(stream);

                    self.full_propagate_assign_async(ct_left, stream);
                    self.full_propagate_assign_async(&mut tmp_rhs, stream);
                    (ct_left, &tmp_rhs)
                }
            }
        };
        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::And, stream);
    }

    pub fn bitand_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.bitand_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitor(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn bitor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.bitor_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn bitor_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_assign_async(ct_left, stream);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(ct_left, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
        };

        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::Or, stream);
    }

    pub fn bitor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.bitor_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitxor(&d_ct1, &d_ct2, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 ^ msg2);
    /// ```
    pub fn bitxor<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.bitxor_assign(&mut result, ct_right, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn bitxor_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_assign_async(ct_left, stream);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.duplicate_async(stream);

                self.full_propagate_assign_async(ct_left, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct_left, &tmp_rhs)
            }
        };

        self.unchecked_bitop_assign_async(lhs, rhs, BitOpType::Xor, stream);
    }

    pub fn bitxor_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.bitxor_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 1u64;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let d_ct_res = sks.bitnot(&d_ct, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, !msg % 256);
    /// ```
    pub fn bitnot<T: CudaIntegerRadixCiphertext>(&self, ct: &T, stream: &CudaStream) -> T {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.bitnot_assign(&mut result, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn bitnot_assign_async<T: CudaIntegerRadixCiphertext>(
        &self,
        ct: &mut T,
        stream: &CudaStream,
    ) {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }

        self.unchecked_bitnot_assign_async(ct, stream);
    }

    pub fn bitnot_assign<T: CudaIntegerRadixCiphertext>(&self, ct: &mut T, stream: &CudaStream) {
        unsafe {
            self.bitnot_assign_async(ct, stream);
        }
        stream.synchronize();
    }
}
