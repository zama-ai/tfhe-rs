use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaDynamicKeyswitchingKey};
use crate::integer::gpu::{cuda_backend_unchecked_bitonic_sort, CudaServerKey, PBSType};

impl CudaServerKey {
    /// Sort `values` ascending with a bitonic network. Requires a power-of-two
    /// length and clean carries
    pub fn unchecked_bitonic_sort<T: CudaIntegerRadixCiphertext>(
        &self,
        values: &mut [T],
        streams: &CudaStreams,
    ) {
        assert!(
            values.len().is_power_of_two(),
            "Bitonic sort requires a power-of-two number of values, got {}",
            values.len()
        );
        if values.len() <= 1 {
            return;
        }

        let num_blocks = values[0].as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let mut radix_refs: Vec<_> = values.iter_mut().map(|v| v.as_mut()).collect();

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_bitonic_sort(
                        streams,
                        &mut radix_refs,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        num_blocks,
                        T::IS_SIGNED,
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                        1,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_unchecked_bitonic_sort(
                        streams,
                        &mut radix_refs,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        num_blocks,
                        T::IS_SIGNED,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                        1,
                    );
                }
            }
        }
    }

    /// Sort `values` ascending with a bitonic network.
    /// Requires a power-of-two length.
    pub fn bitonic_sort<T: CudaIntegerRadixCiphertext>(
        &self,
        values: &mut [T],
        streams: &CudaStreams,
    ) {
        for v in values.iter_mut() {
            if !v.block_carries_are_empty() {
                self.full_propagate_assign(v, streams);
            }
        }
        self.unchecked_bitonic_sort(values, streams);
    }
}
