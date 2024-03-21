use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
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
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.add(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.add_assign(&mut result, ct_right, stream);
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
        self.unchecked_add_assign_async(lhs, rhs, stream);
        self.propagate_single_carry_assign_async(lhs, stream);
    }

    pub fn add_assign<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
        stream: &CudaStream,
    ) {
        unsafe {
            self.add_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 10;
    /// let msg2 = 127;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let d_ct2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct2, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_add(&d_ct1, &d_ct2, &mut stream);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn unchecked_add<T: CudaIntegerRadixCiphertext>(
        &self,
        ct_left: &T,
        ct_right: &T,
        stream: &CudaStream,
    ) -> T {
        let mut result = unsafe { ct_left.duplicate_async(stream) };
        self.unchecked_add_assign(&mut result, ct_right, stream);
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
        stream: &CudaStream,
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

        stream.unchecked_add_integer_radix_assign_async(
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
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_add_assign_async(ct_left, ct_right, stream);
        }
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_sum_ciphertexts_assign_async(
        &self,
        result: &mut CudaUnsignedRadixCiphertext,
        ciphertexts: &[CudaUnsignedRadixCiphertext],
        stream: &CudaStream,
    ) {
        if ciphertexts.is_empty() {
            return;
        }

        result
            .as_mut()
            .d_blocks
            .0
            .d_vec
            .copy_from_gpu_async(&ciphertexts[0].as_ref().d_blocks.0.d_vec, stream);
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
            self.add_assign_async(result, &ciphertexts[1], stream);
            return;
        }

        let radix_count_in_vec = ciphertexts.len();

        let mut terms = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            ciphertexts
                .iter()
                .map(|ciphertext| &ciphertext.as_ref().d_blocks),
            stream,
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_sum_ciphertexts_integer_radix_classic_kb_assign_async(
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_sum_ciphertexts_integer_radix_multibit_kb_assign_async(
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
                    d_multibit_bsk.grouping_factor,
                    num_blocks.0 as u32,
                    radix_count_in_vec as u32,
                );
            }
        }
    }

    pub fn unchecked_sum_ciphertexts(
        &self,
        ciphertexts: &[CudaUnsignedRadixCiphertext],
        stream: &CudaStream,
    ) -> Option<CudaUnsignedRadixCiphertext> {
        if ciphertexts.is_empty() {
            return None;
        }

        let mut result = unsafe { ciphertexts[0].duplicate_async(stream) };

        if ciphertexts.len() == 1 {
            return Some(result);
        }

        unsafe { self.unchecked_sum_ciphertexts_assign_async(&mut result, ciphertexts, stream) };
        stream.synchronize();
        Some(result)
    }

    pub fn sum_ciphertexts(
        &self,
        mut ciphertexts: Vec<CudaUnsignedRadixCiphertext>,
        stream: &CudaStream,
    ) -> Option<CudaUnsignedRadixCiphertext> {
        if ciphertexts.is_empty() {
            return None;
        }

        unsafe {
            ciphertexts
                .iter_mut()
                .filter(|ct| !ct.block_carries_are_empty())
                .for_each(|ct| {
                    self.full_propagate_assign_async(&mut *ct, stream);
                });
        }

        self.unchecked_sum_ciphertexts(&ciphertexts, stream)
    }
}
