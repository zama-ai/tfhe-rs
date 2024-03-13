use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{BitOpType, CudaServerKey};

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_bitop_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        op: BitOpType,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();
        let message_modulus = self.message_modulus.0;

        let h_clear_blocks = BlockDecomposer::with_early_stop_at_zero(rhs, message_modulus.ilog2())
            .iter_as::<u8>()
            .map(|x| x as u64)
            .collect::<Vec<_>>();

        let clear_blocks = CudaVec::from_cpu_async(&h_clear_blocks, stream);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_bitop_integer_radix_classic_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &clear_blocks,
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
                stream.unchecked_scalar_bitop_integer_radix_multibit_kb_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &clear_blocks,
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

    pub fn unchecked_scalar_bitand<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_bitand_assign(&mut result, rhs, stream);
        result
    }

    pub fn unchecked_scalar_bitand_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarAnd, stream);
            ct.as_mut().info = ct.as_ref().info.after_scalar_bitand(rhs);
        }
        stream.synchronize();
    }

    pub fn unchecked_scalar_bitor<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_bitor_assign(&mut result, rhs, stream);
        result
    }

    pub fn unchecked_scalar_bitor_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarOr, stream);
            ct.as_mut().info = ct.as_ref().info.after_scalar_bitor(rhs);
        }
        stream.synchronize();
    }

    pub fn unchecked_scalar_bitxor<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_bitxor_assign(&mut result, rhs, stream);
        result
    }

    pub fn unchecked_scalar_bitxor_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarXor, stream);
            ct.as_mut().info = ct.as_ref().info.after_scalar_bitxor(rhs);
        }
        stream.synchronize();
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_bitand_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }
        self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarAnd, stream);
        ct.as_mut().info = ct.as_ref().info.after_scalar_bitand(rhs);
    }

    pub fn scalar_bitand_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, stream: &CudaStream)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_bitand_assign_async(ct, rhs, stream);
        }
        stream.synchronize();
    }

    pub fn scalar_bitand<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_bitand_assign(&mut result, rhs, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_bitor_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }
        self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarOr, stream);
        ct.as_mut().info = ct.as_ref().info.after_scalar_bitor(rhs);
    }

    pub fn scalar_bitor_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, stream: &CudaStream)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_bitor_assign_async(ct, rhs, stream);
        }
        stream.synchronize();
    }

    pub fn scalar_bitor<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_bitor_assign(&mut result, rhs, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_bitxor_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        }
        self.unchecked_scalar_bitop_assign_async(ct, rhs, BitOpType::ScalarXor, stream);
        ct.as_mut().info = ct.as_ref().info.after_scalar_bitxor(rhs);
    }

    pub fn scalar_bitxor_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, stream: &CudaStream)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_bitxor_assign_async(ct, rhs, stream);
        }
        stream.synchronize();
    }

    pub fn scalar_bitxor<Scalar, T>(&self, ct: &T, rhs: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_bitxor_assign(&mut result, rhs, stream);
        result
    }
}
