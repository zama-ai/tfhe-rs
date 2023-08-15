use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::ComparisonType;
use crate::integer::server_key::comparator::Comparator;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_comparison_async<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        op: ComparisonType,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        if scalar < T::ZERO {
            // ct represents an unsigned (always >= 0)
            return self.create_trivial_radix(
                Comparator::IS_SUPERIOR,
                ct.d_blocks.lwe_ciphertext_count().0,
                stream,
            );
        }

        let message_modulus = self.message_modulus.0;

        let mut scalar_blocks =
            BlockDecomposer::with_early_stop_at_zero(scalar, message_modulus.ilog2())
                .iter_as::<u64>()
                .collect::<Vec<_>>();

        // scalar is obviously bigger if it has non-zero
        // blocks  after lhs's last block
        let is_scalar_obviously_bigger = scalar_blocks
            .get(ct.d_blocks.lwe_ciphertext_count().0..)
            .is_some_and(|sub_slice| sub_slice.iter().any(|&scalar_block| scalar_block != 0));
        if is_scalar_obviously_bigger {
            return self.create_trivial_radix(
                Comparator::IS_INFERIOR,
                ct.d_blocks.lwe_ciphertext_count().0,
                stream,
            );
        }

        // If we are still here, that means scalar_blocks above
        // num_blocks are 0s, we can remove them
        // as we will handle them separately.
        scalar_blocks.truncate(ct.d_blocks.lwe_ciphertext_count().0);

        let d_scalar_blocks: CudaVec<u64> = CudaVec::from_async(&scalar_blocks, stream);

        let lwe_ciphertext_count = ct.d_blocks.lwe_ciphertext_count();

        let mut result = ct.duplicate_async(stream);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_classic_kb_async(
                    &mut result.d_blocks.0.d_vec,
                    &ct.d_blocks.0.d_vec,
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
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_comparison_integer_radix_multibit_kb_async(
                    &mut result.d_blocks.0.d_vec,
                    &ct.d_blocks.0.d_vec,
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
                );
            }
        }

        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_gt_async<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GT, stream)
    }

    pub fn unchecked_scalar_gt<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::GE, stream)
    }

    pub fn unchecked_scalar_ge<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LT, stream)
    }

    pub fn unchecked_scalar_lt<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::LE, stream)
    }

    pub fn unchecked_scalar_le<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::MAX, stream)
    }

    pub fn unchecked_scalar_max<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
    pub unsafe fn unchecked_scalar_min_async<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        self.unchecked_scalar_comparison_async(ct, scalar, ComparisonType::MIN, stream)
    }

    pub fn unchecked_scalar_min<T>(
        &self,
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
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
        ct: &CudaRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaRadixCiphertext
    where
        T: DecomposableInto<u64>,
    {
        let result = unsafe { self.scalar_min_async(ct, scalar, stream) };
        stream.synchronize();
        result
    }
}
