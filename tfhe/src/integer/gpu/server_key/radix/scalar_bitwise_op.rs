use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    cuda_backend_get_full_propagate_assign_size_on_gpu, cuda_backend_get_scalar_bitop_size_on_gpu,
    cuda_backend_unchecked_scalar_bitop_assign, BitOpType, CudaServerKey, PBSType,
};

impl CudaServerKey {
    pub fn unchecked_scalar_bitop_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        op: BitOpType,
        streams: &CudaStreams,
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

        let clear_blocks = unsafe { CudaVec::from_cpu_async(&h_clear_blocks, streams, 0) };
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_scalar_bitop_assign(
                        streams,
                        ct.as_mut(),
                        &clear_blocks,
                        &h_clear_blocks,
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_scalar_bitop_assign(
                        streams,
                        ct.as_mut(),
                        &clear_blocks,
                        &h_clear_blocks,
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
                        op,
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn unchecked_scalar_bitand<Scalar, T>(
        &self,
        ct: &T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_bitand_assign(&mut result, rhs, streams);
        result
    }

    pub fn unchecked_scalar_bitand_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarAnd, streams);
    }

    pub fn unchecked_scalar_bitor<Scalar, T>(&self, ct: &T, rhs: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_bitor_assign(&mut result, rhs, streams);
        result
    }

    pub fn unchecked_scalar_bitor_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarOr, streams);
    }

    pub fn unchecked_scalar_bitxor<Scalar, T>(
        &self,
        ct: &T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.unchecked_scalar_bitxor_assign(&mut result, rhs, streams);
        result
    }

    pub fn unchecked_scalar_bitxor_assign<Scalar, T>(
        &self,
        ct: &mut T,
        rhs: Scalar,
        streams: &CudaStreams,
    ) where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarXor, streams);
    }

    pub fn scalar_bitand_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarAnd, streams);
    }

    pub fn scalar_bitand<Scalar, T>(&self, ct: &T, rhs: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_bitand_assign(&mut result, rhs, streams);
        result
    }

    pub fn scalar_bitor_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarOr, streams);
    }

    pub fn scalar_bitor<Scalar, T>(&self, ct: &T, rhs: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_bitor_assign(&mut result, rhs, streams);
        result
    }

    pub fn scalar_bitxor_assign<Scalar, T>(&self, ct: &mut T, rhs: Scalar, streams: &CudaStreams)
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign(ct, streams);
        }
        self.unchecked_scalar_bitop_assign(ct, rhs, BitOpType::ScalarXor, streams);
    }

    pub fn scalar_bitxor<Scalar, T>(&self, ct: &T, rhs: Scalar, streams: &CudaStreams) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = ct.duplicate(streams);
        self.scalar_bitxor_assign(&mut result, rhs, streams);
        result
    }
    pub fn get_scalar_bitop_size_on_gpu<T>(
        &self,
        ct: &T,
        op: BitOpType,
        streams: &CudaStreams,
    ) -> u64
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
        let clear_blocks_mem = (lwe_ciphertext_count.0 * size_of::<u64>()) as u64;

        let scalar_bitop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_scalar_bitop_size_on_gpu(
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
                op,
                lwe_ciphertext_count.0 as u32,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_scalar_bitop_size_on_gpu(
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
                    op,
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        full_prop_mem.max(scalar_bitop_mem + clear_blocks_mem)
    }

    pub fn get_scalar_bitand_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.get_scalar_bitop_size_on_gpu(ct, BitOpType::ScalarAnd, streams)
    }
    pub fn get_scalar_bitor_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.get_scalar_bitop_size_on_gpu(ct, BitOpType::ScalarOr, streams)
    }
    pub fn get_scalar_bitxor_size_on_gpu<T>(&self, ct: &T, streams: &CudaStreams) -> u64
    where
        T: CudaIntegerRadixCiphertext,
    {
        self.get_scalar_bitop_size_on_gpu(ct, BitOpType::ScalarXor, streams)
    }
}
