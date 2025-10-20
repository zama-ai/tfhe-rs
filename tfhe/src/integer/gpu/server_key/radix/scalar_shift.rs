use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CastFrom, LweBskGroupingFactor};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu,
    cuda_backend_get_scalar_left_shift_size_on_gpu,
    cuda_backend_get_scalar_logical_right_shift_size_on_gpu,
    cuda_backend_unchecked_scalar_arithmetic_right_shift_assign,
    cuda_backend_unchecked_scalar_left_shift_assign,
    cuda_backend_unchecked_scalar_logical_right_shift_assign, CudaServerKey, PBSType,
};

impl CudaServerKey {
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
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
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_left_shift_assign(&mut result, shift, streams);
        result
    }

    pub fn unchecked_scalar_left_shift_assign<Scalar, T>(
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

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_scalar_left_shift_assign(
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
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_scalar_left_shift_assign(
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
                        None,
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
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
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_right_shift_assign(&mut result, shift, streams);
        result
    }

    pub fn unchecked_scalar_right_shift_assign<Scalar, T>(
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

        unsafe {
            if T::IS_SIGNED {
                match &self.bootstrapping_key {
                    CudaBootstrappingKey::Classic(d_bsk) => {
                        cuda_backend_unchecked_scalar_arithmetic_right_shift_assign(
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
                            d_bsk.ms_noise_reduction_configuration.as_ref(),
                        );
                    }
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                        cuda_backend_unchecked_scalar_arithmetic_right_shift_assign(
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
                            None,
                        );
                    }
                }
            } else {
                match &self.bootstrapping_key {
                    CudaBootstrappingKey::Classic(d_bsk) => {
                        cuda_backend_unchecked_scalar_logical_right_shift_assign(
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
                            d_bsk.ms_noise_reduction_configuration.as_ref(),
                        );
                    }
                    CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                        cuda_backend_unchecked_scalar_logical_right_shift_assign(
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
                            None,
                        );
                    }
                }
            }
        }
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
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_right_shift_assign(ct, shift, streams);
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
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
        let mut result = ct.duplicate(streams);
        self.scalar_right_shift_assign(&mut result, shift, streams);
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, size, &streams);
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
        let mut result = ct.duplicate(streams);
        self.scalar_left_shift_assign(&mut result, shift, streams);
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
            self.full_propagate_assign(ct, streams);
        }

        self.unchecked_scalar_left_shift_assign(ct, shift, streams);
    }

    pub fn get_scalar_left_shift_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

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
        let scalar_shift_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_scalar_left_shift_size_on_gpu(
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
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_scalar_left_shift_size_on_gpu(
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
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        full_prop_mem.max(scalar_shift_mem)
    }

    pub fn get_scalar_right_shift_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

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
        let scalar_shift_mem = if T::IS_SIGNED {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu(
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_get_scalar_arithmetic_right_shift_size_on_gpu(
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    )
                }
            }
        } else {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_get_scalar_logical_right_shift_size_on_gpu(
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    )
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_get_scalar_logical_right_shift_size_on_gpu(
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    )
                }
            }
        };
        full_prop_mem.max(scalar_shift_mem)
    }
}
