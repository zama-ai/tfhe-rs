use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, LweBskGroupingFactor, LweCiphertextCount};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::info::CudaRadixCiphertextInfo;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    unchecked_scalar_comparison_integer_radix_kb_async, ComparisonType, PBSType,
};
use crate::shortint::ciphertext::Degree;

impl CudaServerKey {
    /// Returns whether the clear scalar is outside of the
    /// value range the ciphertext can hold.
    ///
    /// - Returns None if the scalar is in the range of values that the ciphertext can represent
    ///
    /// - Returns Some(ordering) when the scalar is out of representable range of the ciphertext.
    ///     - Equal will never be returned
    ///     - Less means the scalar is less than the min value representable by the ciphertext
    ///     - Greater means the scalar is greater that the max value representable by the ciphertext
    pub(crate) fn is_scalar_out_of_bounds<T, Scalar>(
        &self,
        ct: &T,
        scalar: Scalar,
    ) -> Option<std::cmp::Ordering>
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, self.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        let ct_len = ct.as_ref().d_blocks.lwe_ciphertext_count();
        if T::IS_SIGNED {
            let sign_bit_pos = self.message_modulus.0.ilog2() - 1;
            let sign_bit_is_set = scalar_blocks
                .get(ct_len.0 - 1)
                .map_or(false, |block| (block >> sign_bit_pos) == 1);

            if scalar > Scalar::ZERO
                && (scalar_blocks.len() > ct_len.0
                    || (scalar_blocks.len() == ct_len.0 && sign_bit_is_set))
            {
                // If scalar is positive and that any bits above the ct's n-1 bits is set
                // it means scalar is bigger.
                //
                // This is checked in two step
                // - If there a more scalar blocks than ct blocks then ct is trivially bigger
                // - If there are the same number of blocks but the "sign bit" / msb of st scalar is
                //   set then, the scalar is trivially bigger
                return Some(std::cmp::Ordering::Greater);
            } else if scalar < Scalar::ZERO {
                // If scalar is negative, and that any bits above the ct's n-1 bits is not set
                // it means scalar is smaller.

                if ct_len.0 > scalar_blocks.len() {
                    // Ciphertext has more blocks, the scalar may be in range
                    return None;
                }

                // (returns false for empty iter)
                let at_least_one_block_is_not_full_of_1s = scalar_blocks[ct_len.0..]
                    .iter()
                    .any(|&scalar_block| scalar_block != (self.message_modulus.0 as u64 - 1));

                let sign_bit_pos = self.message_modulus.0.ilog2() - 1;
                let sign_bit_is_unset = scalar_blocks
                    .get(ct_len.0 - 1)
                    .map_or(false, |block| (block >> sign_bit_pos) == 0);

                if at_least_one_block_is_not_full_of_1s || sign_bit_is_unset {
                    // Scalar is smaller than lowest value of T
                    return Some(std::cmp::Ordering::Less);
                }
            }
        } else {
            // T is unsigned
            if scalar < Scalar::ZERO {
                // ct represent an unsigned (always >= 0)
                return Some(std::cmp::Ordering::Less);
            } else if scalar > Scalar::ZERO {
                // scalar is obviously bigger if it has non-zero
                // blocks  after lhs's last block
                let is_scalar_obviously_bigger =
                    scalar_blocks.get(ct_len.0..).is_some_and(|sub_slice| {
                        sub_slice.iter().any(|&scalar_block| scalar_block != 0)
                    });
                if is_scalar_obviously_bigger {
                    return Some(std::cmp::Ordering::Greater);
                }
            }
        }

        None
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_signed_and_unsigned_scalar_comparison_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        op: ComparisonType,
        signed_with_positive_scalar: bool,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if scalar < Scalar::ZERO {
            // ct represents an unsigned (always >= 0)
            let value = match op {
                ComparisonType::GT | ComparisonType::GE | ComparisonType::NE => 1,
                _ => 0,
            };
            let ct_res: T = self.create_trivial_radix(value, 1, stream);
            return CudaBooleanBlock::from_cuda_radix_ciphertext(ct_res.into_inner());
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
            let value = match op {
                ComparisonType::LT | ComparisonType::LE | ComparisonType::NE => 1,
                _ => 0,
            };
            let ct_res: T = self.create_trivial_radix(value, 1, stream);
            return CudaBooleanBlock::from_cuda_radix_ciphertext(ct_res.into_inner());
        }

        // If we are still here, that means scalar_blocks above
        // num_blocks are 0s, we can remove them
        // as we will handle them separately.
        scalar_blocks.truncate(ct.as_ref().d_blocks.lwe_ciphertext_count().0);

        let d_scalar_blocks: CudaVec<u64> = CudaVec::from_cpu_async(&scalar_blocks, stream, 0);

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
                unchecked_scalar_comparison_integer_radix_kb_async(
                    stream,
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
                    signed_with_positive_scalar,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_scalar_comparison_integer_radix_kb_async(
                    stream,
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
                    lwe_ciphertext_count.0 as u32,
                    scalar_blocks.len() as u32,
                    op,
                    signed_with_positive_scalar,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_comparison_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        op: ComparisonType,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0;

        if T::IS_SIGNED {
            match self.is_scalar_out_of_bounds(ct, scalar) {
                Some(std::cmp::Ordering::Greater) => {
                    // Scalar is greater than the bounds, so ciphertext is smaller
                    let result: T = match op {
                        ComparisonType::LT | ComparisonType::LE => {
                            self.create_trivial_radix(1, num_blocks, stream)
                        }
                        _ => self.create_trivial_radix(
                            0,
                            ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                            stream,
                        ),
                    };
                    return CudaBooleanBlock::from_cuda_radix_ciphertext(result.into_inner());
                }
                Some(std::cmp::Ordering::Less) => {
                    // Scalar is smaller than the bounds, so ciphertext is bigger
                    let result: T = match op {
                        ComparisonType::GT | ComparisonType::GE => {
                            self.create_trivial_radix(1, num_blocks, stream)
                        }
                        _ => self.create_trivial_radix(
                            0,
                            ct.as_ref().d_blocks.lwe_ciphertext_count().0,
                            stream,
                        ),
                    };
                    return CudaBooleanBlock::from_cuda_radix_ciphertext(result.into_inner());
                }
                Some(std::cmp::Ordering::Equal) => unreachable!("Internal error: invalid value"),
                None => {
                    // scalar is in range, fallthrough
                }
            }

            if scalar >= Scalar::ZERO {
                self.unchecked_signed_and_unsigned_scalar_comparison_async(
                    ct, scalar, op, true, stream,
                )
            } else {
                let scalar_as_trivial = self.create_trivial_radix(scalar, num_blocks, stream);
                self.unchecked_comparison_async(ct, &scalar_as_trivial, op, stream)
            }
        } else {
            // Unsigned
            self.unchecked_signed_and_unsigned_scalar_comparison_async(
                ct, scalar, op, false, stream,
            )
        }
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_minmax_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        op: ComparisonType,
        stream: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let message_modulus = self.message_modulus.0;

        let scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, message_modulus.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        let d_scalar_blocks: CudaVec<u64> = CudaVec::from_cpu_async(&scalar_blocks, stream, 0);

        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

        let mut result = ct.duplicate_async(stream);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_scalar_comparison_integer_radix_kb_async(
                    stream,
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
                    T::IS_SIGNED,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_scalar_comparison_integer_radix_kb_async(
                    stream,
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
                    lwe_ciphertext_count.0 as u32,
                    scalar_blocks.len() as u32,
                    op,
                    T::IS_SIGNED,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_eq_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::EQ, stream)
    }

    pub fn unchecked_scalar_eq<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_eq_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_eq_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
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
    pub fn scalar_eq<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_eq_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_ne_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
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
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let mut stream = CudaStreams::new_single_gpu(gpu_index);
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
    pub fn scalar_ne<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_ne_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_ne_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::NE, stream)
    }

    pub fn unchecked_scalar_ne<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        T: CudaIntegerRadixCiphertext,
        Scalar: DecomposableInto<u64>,
    {
        let result = unsafe { self.unchecked_scalar_ne_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_gt_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GT, stream)
    }

    pub fn unchecked_scalar_gt<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_gt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_ge_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GE, stream)
    }

    pub fn unchecked_scalar_ge<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_ge_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_lt_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LT, stream)
    }

    pub fn unchecked_scalar_lt<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_lt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_le_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LE, stream)
    }

    pub fn unchecked_scalar_le<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_le_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_gt_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_gt<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_gt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_ge_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_ge<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_ge_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_lt_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_lt<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_lt_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_le_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_le<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> CudaBooleanBlock
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_le_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_max_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_minmax_async(ct, scalar, ComparisonType::MAX, stream)
    }

    pub fn unchecked_scalar_max<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_max_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_min_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_minmax_async(ct, scalar, ComparisonType::MIN, stream)
    }

    pub fn unchecked_scalar_min<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.unchecked_scalar_min_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_max_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_max<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_max_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_min_async<Scalar, T>(
        &self,
        ct: &T,
        scalar: Scalar,
        stream: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
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

    pub fn scalar_min<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let result = unsafe { self.scalar_min_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
}
