use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    unchecked_rotate_left_integer_radix_kb_assign_async,
    unchecked_rotate_right_integer_radix_kb_assign_async, CudaServerKey, PBSType,
};
use tfhe_core_crypto::gpu::CudaStreams;
use tfhe_core_crypto::prelude::LweBskGroupingFactor;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_rotate_right_assign_async<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let is_signed = T::IS_SIGNED;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_rotate_right_integer_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &rotate.as_ref().d_blocks.0.d_vec,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_rotate_right_integer_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &rotate.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_rotate_right_async<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.unchecked_rotate_right_assign_async(&mut result, rotate, streams);
        result
    }

    pub fn unchecked_rotate_right<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_rotate_right_async(ct, rotate, streams) };
        streams.synchronize();
        result
    }

    pub fn unchecked_rotate_right_assign<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_rotate_right_assign_async(ct, rotate, streams);
        }
        streams.synchronize();
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_rotate_left_assign_async<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let is_signed = T::IS_SIGNED;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_rotate_left_integer_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &rotate.as_ref().d_blocks.0.d_vec,
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
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_rotate_left_integer_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &rotate.as_ref().d_blocks.0.d_vec,
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
                    is_signed,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn unchecked_rotate_left_async<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate_async(streams);
        self.unchecked_rotate_left_assign_async(&mut result, rotate, streams);
        result
    }

    pub fn unchecked_rotate_left<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_rotate_left_async(ct, rotate, streams) };
        streams.synchronize();
        result
    }

    pub fn unchecked_rotate_left_assign<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_rotate_left_assign_async(ct, rotate, streams);
        }
        streams.synchronize();
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn rotate_right_async<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                (&tmp_lhs, rotate)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(streams);
                tmp_rhs = rotate.duplicate_async(streams);

                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        let mut result = lhs.duplicate_async(streams);
        self.unchecked_rotate_right_assign_async(&mut result, rhs, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn rotate_right_assign_async<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                (&mut tmp_lhs, rotate)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(streams);
                tmp_rhs = rotate.duplicate_async(streams);

                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (&mut tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_rotate_right_assign_async(lhs, rhs, streams);
    }

    /// Computes homomorphically a right rotate by an encrypted amount
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 128u8;
    /// let rotate = 2u8;
    ///
    /// let ct = cks.encrypt(msg);
    /// let rotate_ct = cks.encrypt(rotate);
    /// // Copy to GPU
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    /// let mut d_rotate_ct =
    ///     CudaUnsignedRadixCiphertext::from_radix_ciphertext(&rotate_ct, &streams);
    ///
    /// let d_ct_res = sks.rotate_right(&d_ct, &d_rotate_ct, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg.rotate_right(rotate as u32) as u64);
    /// ```
    pub fn rotate_right<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.rotate_right_async(ct, rotate, streams) };
        streams.synchronize();
        result
    }

    pub fn rotate_right_assign<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.rotate_right_assign_async(ct, rotate, streams) };
        streams.synchronize();
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn rotate_left_async<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                (&tmp_lhs, rotate)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(streams);
                tmp_rhs = rotate.duplicate_async(streams);

                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (&tmp_lhs, &tmp_rhs)
            }
        };

        let mut result = lhs.duplicate_async(streams);
        self.unchecked_rotate_left_assign_async(&mut result, rhs, streams);
        result
    }

    /// # Safety
    ///
    /// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until streams is synchronised
    pub unsafe fn rotate_left_assign_async<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_lhs: T;
        let mut tmp_rhs: CudaUnsignedRadixCiphertext;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            rotate.block_carries_are_empty(),
        ) {
            (true, true) => (ct, rotate),
            (true, false) => {
                tmp_rhs = rotate.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ct.duplicate_async(streams);
                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                (&mut tmp_lhs, rotate)
            }
            (false, false) => {
                tmp_lhs = ct.duplicate_async(streams);
                tmp_rhs = rotate.duplicate_async(streams);

                self.full_propagate_assign_async(&mut tmp_lhs, streams);
                self.full_propagate_assign_async(&mut tmp_rhs, streams);
                (&mut tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_rotate_left_assign_async(lhs, rhs, streams);
    }

    /// Computes homomorphically a right rotate by an encrypted amount
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
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let mut streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));
    ///
    /// let size = 4;
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, size, &streams);
    ///
    /// let msg = 128u8;
    /// let rotate = 2u8;
    ///
    /// let ct = cks.encrypt(msg);
    /// let rotate_ct = cks.encrypt(rotate);
    /// // Copy to GPU
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);
    /// let mut d_rotate_ct =
    ///     CudaUnsignedRadixCiphertext::from_radix_ciphertext(&rotate_ct, &streams);
    ///
    /// let d_ct_res = sks.rotate_left(&d_ct, &d_rotate_ct, &streams);
    ///
    /// // Copy back to CPU
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg.rotate_left(rotate as u32) as u64);
    /// ```
    pub fn rotate_left<T>(
        &self,
        ct: &T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.rotate_left_async(ct, rotate, streams) };
        streams.synchronize();
        result
    }
    pub fn rotate_left_assign<T>(
        &self,
        ct: &mut T,
        rotate: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        unsafe { self.rotate_left_async(ct, rotate, streams) };
        streams.synchronize();
    }
}
