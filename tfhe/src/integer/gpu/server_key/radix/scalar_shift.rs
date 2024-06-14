use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CastFrom, LweBskGroupingFactor};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    unchecked_scalar_arithmetic_right_shift_integer_radix_kb_assign_async,
    unchecked_scalar_left_shift_integer_radix_kb_assign_async,
    unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async, CudaServerKey, PBSType,
};

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_left_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_scalar_left_shift_assign_async(&mut result, shift, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_left_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_scalar_left_shift_integer_radix_kb_assign_async(
                    stream,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    u32::cast_from(shift),
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_scalar_left_shift_integer_radix_kb_assign_async(
                    stream,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    u32::cast_from(shift),
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
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_scalar_left_shift(&d_ct1, shift, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn unchecked_scalar_left_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_left_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_right_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.unchecked_scalar_right_shift_assign_async(&mut result, shift, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_right_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        if T::IS_SIGNED {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    unchecked_scalar_arithmetic_right_shift_integer_radix_kb_assign_async(
                        stream,
                        &mut ct.as_mut().d_blocks.0.d_vec,
                        u32::cast_from(shift),
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    unchecked_scalar_arithmetic_right_shift_integer_radix_kb_assign_async(
                        stream,
                        &mut ct.as_mut().d_blocks.0.d_vec,
                        u32::cast_from(shift),
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                    );
                }
            }
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                        stream,
                        &mut ct.as_mut().d_blocks.0.d_vec,
                        u32::cast_from(shift),
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                        stream,
                        &mut ct.as_mut().d_blocks.0.d_vec,
                        u32::cast_from(shift),
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                    );
                }
            }
        }
    }

    /// Computes homomorphically a right shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    ///
    /// let d_ct_res = sks.unchecked_scalar_right_shift(&d_ct1, shift, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn unchecked_scalar_right_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_right_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_right_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }

        self.unchecked_scalar_right_shift_assign_async(ct, shift, stream);
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_right_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.scalar_right_shift_assign_async(&mut result, shift, stream);
        result
    }

    /// Computes homomorphically a right shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    ///
    /// let d_ct_res = sks.scalar_right_shift(&d_ct1, shift, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn scalar_right_shift<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_right_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_left_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }

        self.unchecked_scalar_left_shift_assign_async(ct, shift, stream);
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_left_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(stream);
        self.scalar_left_shift_assign_async(&mut result, shift, stream);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    ///
    /// let d_ct_res = sks.scalar_left_shift(&d_ct1, shift, &mut stream);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn scalar_left_shift<Scalar, T>(&self, ct: &T, shift: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_left_shift_async(ct, shift, stream) };
        stream.synchronize();
        result
    }

    pub fn scalar_left_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            if !ct.block_carries_are_empty() {
                self.full_propagate_assign_async(ct, stream);
            }

            self.unchecked_scalar_left_shift_assign_async(ct, shift, stream);
        };
        stream.synchronize();
    }

    pub fn scalar_right_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            if !ct.block_carries_are_empty() {
                self.full_propagate_assign_async(ct, stream);
            }

            self.unchecked_scalar_right_shift_assign_async(ct, shift, stream);
        };
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_right_shift_logical_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        stream: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                    stream,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    u32::cast_from(shift),
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                    stream,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    u32::cast_from(shift),
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
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }
    }
}
