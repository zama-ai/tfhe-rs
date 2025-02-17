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
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_left_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.unchecked_scalar_left_shift_assign_async(&mut result, shift, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_left_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_scalar_left_shift_integer_radix_kb_assign_async(
                    streams,
                    ct.as_mut(),
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
                    streams,
                    ct.as_mut(),
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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// # // TODO GPU DRIFT UPDATE
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// # // TODO GPU DRIFT UPDATE
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.unchecked_scalar_left_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn unchecked_scalar_left_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_left_shift_async(ct, shift, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_right_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.unchecked_scalar_right_shift_assign_async(&mut result, shift, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_right_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
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
                        streams,
                        ct.as_mut(),
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    unchecked_scalar_arithmetic_right_shift_integer_radix_kb_assign_async(
                        streams,
                        ct.as_mut(),
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
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                    );
                }
            }
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                        streams,
                        ct.as_mut(),
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
                        streams,
                        ct.as_mut(),
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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// # // TODO GPU DRIFT UPDATE
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// # // TODO GPU DRIFT UPDATE
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.unchecked_scalar_right_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn unchecked_scalar_right_shift<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_right_shift_async(ct, shift, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn scalar_right_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, streams);
        }

        self.unchecked_scalar_right_shift_assign_async(ct, shift, streams);
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn scalar_right_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.scalar_right_shift_assign_async(&mut result, shift, streams);
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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// # // TODO GPU DRIFT UPDATE
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// # // TODO GPU DRIFT UPDATE
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.scalar_right_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg >> shift);
    /// ```
    pub fn scalar_right_shift<Scalar, T>(&self, ct: &T, shift: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_right_shift_async(ct, shift, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn scalar_left_shift_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, streams);
        }

        self.unchecked_scalar_left_shift_assign_async(ct, shift, streams);
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn scalar_left_shift_async<Scalar, T>(
        &self,
        ct: &T,
        shift: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.scalar_left_shift_assign_async(&mut result, shift, streams);
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
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// # // TODO GPU DRIFT UPDATE
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// # // TODO GPU DRIFT UPDATE
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);
    ///
    /// let d_ct_res = sks.scalar_left_shift(&d_ct1, shift, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg << shift);
    /// ```
    pub fn scalar_left_shift<Scalar, T>(&self, ct: &T, shift: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_left_shift_async(ct, shift, streams) };
        streams.synchronize();
        result
    }

    pub fn scalar_left_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            unsafe { self.full_propagate_assign_async(ct, streams) };
        }

        unsafe {
            self.unchecked_scalar_left_shift_assign_async(ct, shift, streams);
        };
        streams.synchronize();
    }

    pub fn scalar_right_shift_assign<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            unsafe { self.full_propagate_assign_async(ct, streams) };
        }

        unsafe {
            self.unchecked_scalar_right_shift_assign_async(ct, shift, streams);
        };
        streams.synchronize();
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_scalar_right_shift_logical_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        shift: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: CastFrom<u32>,
        u32: CastFrom<Scalar>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_scalar_logical_right_shift_integer_radix_kb_assign_async(
                    streams,
                    ct.as_mut(),
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
                    streams,
                    ct.as_mut(),
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
