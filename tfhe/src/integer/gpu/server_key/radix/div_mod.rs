use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{
    cuda_backend_get_div_rem_size_on_gpu, cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_unchecked_div_rem_assign, PBSType,
};

impl CudaServerKey {
    pub fn unchecked_div_rem_assign<T>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        // TODO add asserts from `unchecked_div_rem_parallelized`
        let num_blocks = divisor.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;
        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_div_rem_assign(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        numerator.as_ref(),
                        divisor.as_ref(),
                        T::IS_SIGNED,
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
                        num_blocks,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_div_rem_assign(
                        streams,
                        quotient.as_mut(),
                        remainder.as_mut(),
                        numerator.as_ref(),
                        divisor.as_ref(),
                        T::IS_SIGNED,
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
                        num_blocks,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
    }

    pub fn unchecked_div_rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut quotient = numerator.duplicate(streams);
        let mut remainder = numerator.duplicate(streams);

        self.unchecked_div_rem_assign(&mut quotient, &mut remainder, numerator, divisor, streams);
        (quotient, remainder)
    }

    pub fn div_rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> (T, T)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.duplicate(streams);
                self.full_propagate_assign(&mut tmp_divisor, streams);
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = numerator.duplicate(streams);
                self.full_propagate_assign(&mut tmp_numerator, streams);
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.duplicate(streams);
                tmp_numerator = numerator.duplicate(streams);
                self.full_propagate_assign(&mut tmp_numerator, streams);
                self.full_propagate_assign(&mut tmp_divisor, streams);
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem(numerator, divisor, streams)
    }

    pub fn div_rem_assign<T>(
        &self,
        quotient: &mut T,
        remainder: &mut T,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) where
        T: CudaIntegerRadixCiphertext,
    {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.duplicate(streams);
                self.full_propagate_assign(&mut tmp_divisor, streams);
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = numerator.duplicate(streams);
                self.full_propagate_assign(&mut tmp_numerator, streams);
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.duplicate(streams);
                tmp_numerator = numerator.duplicate(streams);
                self.full_propagate_assign(&mut tmp_numerator, streams);
                self.full_propagate_assign(&mut tmp_divisor, streams);
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem_assign(quotient, remainder, numerator, divisor, streams);
    }

    pub fn div<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let (q, _r) = self.div_rem(numerator, divisor, streams);
        q
    }

    pub fn rem<T>(&self, numerator: &T, divisor: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let (_q, r) = self.div_rem(numerator, divisor, streams);
        r
    }
    pub fn div_assign<T>(&self, numerator: &mut T, divisor: &T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut remainder = numerator.duplicate(streams);
        self.div_rem_assign(
            numerator,
            &mut remainder,
            &numerator.duplicate(streams),
            divisor,
            streams,
        );
    }

    pub fn rem_assign<T>(&self, numerator: &mut T, divisor: &T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut quotient = numerator.duplicate(streams);
        self.div_rem_assign(
            &mut quotient,
            numerator,
            &numerator.duplicate(streams),
            divisor,
            streams,
        );
    }
    pub fn get_div_rem_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            numerator.as_ref().d_blocks.lwe_dimension(),
            divisor.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            numerator.as_ref().d_blocks.lwe_ciphertext_count(),
            divisor.as_ref().d_blocks.lwe_ciphertext_count()
        );
        let full_prop_mem = match &self.bootstrapping_key {
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
        };
        let actual_full_prop_mem = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => 0,
            (true, false) => self.get_ciphertext_size_on_gpu(divisor) + full_prop_mem,
            (false, true) => full_prop_mem,
            (false, false) => self.get_ciphertext_size_on_gpu(divisor) + full_prop_mem,
        };

        let lwe_ciphertext_count = numerator.as_ref().d_blocks.lwe_ciphertext_count();

        let mul_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_div_rem_size_on_gpu(
                streams,
                T::IS_SIGNED,
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
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => cuda_backend_get_div_rem_size_on_gpu(
                streams,
                T::IS_SIGNED,
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
            ),
        };
        actual_full_prop_mem.max(mul_mem)
    }

    pub fn get_rem_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_div_rem_size_on_gpu(numerator, divisor, streams)
            + self.get_ciphertext_size_on_gpu(numerator)
    }

    pub fn get_div_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        numerator: &T,
        divisor: &T,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_div_rem_size_on_gpu(numerator, divisor, streams)
            + self.get_ciphertext_size_on_gpu(numerator)
    }
}
