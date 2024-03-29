use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{CiphertextModulus, LweCiphertextCount};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::ComparisonType;
use crate::integer::server_key::comparator::Comparator;
use crate::shortint::ciphertext::Degree;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_comparison_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        op: ComparisonType,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        if scalar < T::ZERO {
            // ct represents an unsigned (always >= 0)
            let ct_res = self.create_trivial_radix(Comparator::IS_SUPERIOR, 1, stream);
            return CudaBooleanBlock::from_cuda_radix_ciphertext(CudaRadixCiphertext::new(
                ct_res.ciphertext.d_blocks,
                ct_res.ciphertext.info,
            ));
        }

        let message_modulus = self.message_modulus.0;

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, message_modulus.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        // scalar is obviously bigger if it has non-zero
        // blocks  after lhs's last block
        let is_scalar_obviously_bigger = scalar_blocks
            .get(ct.as_ref().d_blocks.lwe_ciphertext_count().0..)
            .is_some_and(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0));
        if is_scalar_obviously_bigger {
            let ct_res = self.create_trivial_radix(Comparator::IS_INFERIOR, 1, stream);
            return CudaBooleanBlock::from_cuda_radix_ciphertext(CudaRadixCiphertext::new(
                ct_res.ciphertext.d_blocks,
                ct_res.ciphertext.info,
            ));
        }

        // If we are still here, that means scalar_blocks above
        // num_blocks are 0s, we can remove them
        // as we will handle them separately.
        scalar_blocks.truncate(ct.as_ref().d_blocks.lwe_ciphertext_count().0);

        let d_scalar_blocks: CudaVec<u64> = CudaVec::from_cpu_async(&scalar_blocks, stream);

        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        let block = CudaLweCiphertextList::new(
            ct.as_ref().d_blocks.lwe_dimension(),
            LweCiphertextCount(1),
            CiphertextModulus::new_native(),
            stream,
        );
        let mut block_info = ct.as_ref().info.blocks[0];
        block_info.degree = Degree::new(0);
        let ct_info = vec![block_info];
        let ct_info = CudaRadixCiphertextInfo { blocks: ct_info };

        let mut result =
            CudaBooleanBlock::from_cuda_radix_ciphertext(CudaRadixCiphertext::new(block, ct_info));

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_classic_kb_async(
                    &mut result.as_mut().ciphertext.d_blocks.0.d_vec,
                    &ct.as_ref().d_blocks.0.d_vec,
                    &d_scalar_blocks,
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
                    scalar_blocks.len() as u32,
                    op,
                    false,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_multibit_kb_async(
                    &mut result.as_mut().ciphertext.d_blocks.0.d_vec,
                    &ct.as_ref().d_blocks.0.d_vec,
                    &d_scalar_blocks,
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
                    scalar_blocks.len() as u32,
                    op,
                    false,
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_minmax_async<Scalar>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        op: ComparisonType,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: DecomposableInto<u64>,
    {
        if scalar < Scalar::ZERO {
            // ct represents an unsigned (always >= 0)
            return self.create_trivial_radix(Comparator::IS_SUPERIOR, 1, stream);
        }

        let message_modulus = self.message_modulus.0;

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, message_modulus.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        // scalar is obviously bigger if it has non-zero
        // blocks  after lhs's last block
        let is_scalar_obviously_bigger = scalar_blocks
            .get(ct.as_ref().d_blocks.lwe_ciphertext_count().0..)
            .is_some_and(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0));
        if is_scalar_obviously_bigger {
            return self.create_trivial_radix(Comparator::IS_INFERIOR, 1, stream);
        }

        // If we are still here, that means scalar_blocks above
        // num_blocks are 0s, we can remove them
        // as we will handle them separately.
        scalar_blocks.truncate(ct.as_ref().d_blocks.lwe_ciphertext_count().0);

        let d_scalar_blocks: CudaVec<u64> = CudaVec::from_cpu_async(&scalar_blocks, stream);

        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        let mut result = CudaUnsignedRadixCiphertext {
            ciphertext: ct.as_ref().duplicate_async(stream),
        };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_classic_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct.as_ref().d_blocks.0.d_vec,
                    &d_scalar_blocks,
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
                    scalar_blocks.len() as u32,
                    op,
                    false,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_multibit_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &ct.as_ref().d_blocks.0.d_vec,
                    &d_scalar_blocks,
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
                    scalar_blocks.len() as u32,
                    op,
                    false,
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_eq_async<Scalar>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::EQ, stream)
    }

    pub fn unchecked_scalar_eq<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_eq_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_eq_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_eq_async(lhs, scalar, stream)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &stream);
    ///
    /// let d_ct_res = sks.scalar_eq(&d_ct1, msg2, &stream);
    ///
    /// // Copy the result back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 == msg2);
    /// ```
    pub fn scalar_eq<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_eq_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_ne_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_ne_async(lhs, scalar, stream)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs != rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &stream);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Copy to GPU
    /// let mut d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &stream);
    ///
    /// let d_ct_res = sks.scalar_ne(&d_ct1, msg2, &stream);
    ///
    /// // Copy the result back to CPU
    /// let ct_res = d_ct_res.to_boolean_block(&stream);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, msg1 != msg2);
    /// ```
    pub fn scalar_ne<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_ne_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_ne_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::NE, stream)
    }

    pub fn unchecked_scalar_ne<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_ne_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_gt_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GT, stream)
    }

    pub fn unchecked_scalar_gt<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_gt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_ge_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GE, stream)
    }

    pub fn unchecked_scalar_ge<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_ge_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_lt_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LT, stream)
    }

    pub fn unchecked_scalar_lt<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_lt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_le_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LE, stream)
    }

    pub fn unchecked_scalar_le<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_le_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_gt_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_gt_async(lhs, scalar, stream)
    }

    pub fn scalar_gt<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_gt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_ge_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_ge_async(lhs, scalar, stream)
    }

    pub fn scalar_ge<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_ge_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_lt_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_lt_async(lhs, scalar, stream)
    }

    pub fn scalar_lt<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_lt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_le_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_le_async(lhs, scalar, stream)
    }

    pub fn scalar_le<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaBooleanBlock
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_le_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_max_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_minmax_async(ct, scalar, ComparisonType::MAX, stream)
    }

    pub fn unchecked_scalar_max<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_max_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_min_async<Scalar>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: DecomposableInto<u64>,
    {
        self.unchecked_scalar_minmax_async(ct, scalar, ComparisonType::MIN, stream)
    }

    pub fn unchecked_scalar_min<Scalar>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: Scalar,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        Scalar: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_min_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_max_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_max_async(lhs, scalar, stream)
    }

    pub fn scalar_max<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_max_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_min_async<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_lhs = ct.duplicate_async(stream);
            self.full_propagate_assign_async(&mut tmp_lhs, stream);
            &tmp_lhs
        };

        self.unchecked_scalar_min_async(lhs, scalar, stream)
    }

    pub fn scalar_min<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_min_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
}
