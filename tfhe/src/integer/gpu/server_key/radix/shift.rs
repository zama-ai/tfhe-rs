use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::CudaServerKey;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_right_shift_assign_async<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let is_signed = T::IS_SIGNED;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_shift_right_integer_radix_classic_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &shift.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_shift_right_integer_radix_multibit_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &shift.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                );
            }
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_right_shift_async<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_right_shift_assign_async(&mut result, shift, stream);
        result
    }

    pub fn unchecked_right_shift<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_right_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    pub fn unchecked_right_shift_assign<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.unchecked_right_shift_assign_async(ct, shift, stream) };
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_left_shift_assign_async<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let is_signed = T::IS_SIGNED;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_shift_left_integer_radix_classic_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &shift.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_shift_left_integer_radix_multibit_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &shift.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                );
            }
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_left_shift_async<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_left_shift_assign_async(&mut result, shift, stream);
        result
    }

    pub fn unchecked_left_shift<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_left_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    pub fn unchecked_left_shift_assign<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.unchecked_left_shift_assign_async(ct, shift, stream) };
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn right_shift_async<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, shift)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(stream);
                tmp_rhs = shift.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        let mut result = lhs.duplicate_async(stream);
        self.unchecked_right_shift_assign_async(&mut result, rhs, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn right_shift_assign_async<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&mut tmp_lhs, shift)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(stream);
                tmp_rhs = shift.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&mut tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_right_shift_assign_async(lhs, rhs, stream);
    }

    /// Computes homomorphically a right shift by an encrypted amount
    ///
    /// The result is returned as a new ciphertext.
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    /// let shift_ct = cks.encrypt(shift as u64);
    /// // Copy to GPU
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    /// let mut d_shift_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&shift_ct, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_right_shift(&d_ct, &d_shift_ct, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn right_shift<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.right_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    pub fn right_shift_assign<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.right_shift_assign_async(ct, shift, stream) };
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn left_shift_async<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&tmp_lhs, shift)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(stream);
                tmp_rhs = shift.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        let mut result = lhs.duplicate_async(stream);
        self.unchecked_left_shift_assign_async(&mut result, rhs, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn left_shift_assign_async<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                (&mut tmp_lhs, shift)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(stream);
                tmp_rhs = shift.duplicate_async(stream);

                self.full_propagate_assign_async(&mut tmp_lhs, stream);
                self.full_propagate_assign_async(&mut tmp_rhs, stream);
                (&mut tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_left_shift_assign_async(lhs, rhs, stream);
    }

    /// Computes homomorphically a left shift by an encrypted amount
    ///
    /// The result is returned as a new ciphertext.
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
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    /// let shift_ct = cks.encrypt(shift as u64);
    /// // Copy to GPU
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    /// let mut d_shift_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&shift_ct, &mut stream);
    ///
    /// let d_ct_res = sks.left_shift(&d_ct, &d_shift_ct, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn left_shift<T>(
        &self,
        ct: &T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.left_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    pub fn left_shift_assign<T>(
        &self,
        ct: &mut T,
        shift: &CudaUnsignedRadixCiphertext,
        stream: &CudaStream,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.left_shift_assign_async(ct, shift, stream) };
        stream.synchronize();
    }
}
