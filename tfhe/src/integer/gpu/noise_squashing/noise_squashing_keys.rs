use super::keys::CudaNoiseSquashingKey;
use crate::core_crypto::gpu::lwe_bootstrap_key::{
    CudaLweBootstrapKey, CudaModulusSwitchNoiseReductionConfiguration,
};
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::CompressedShortint128BootstrappingKey;
use crate::shortint::server_key::CompressedModulusSwitchConfiguration;

impl CompressedNoiseSquashingKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaNoiseSquashingKey {
        let compressed_bsk =
            if let CompressedAtomicPatternNoiseSquashingKey::Standard(compressed_nsk) =
                self.key.atomic_pattern()
            {
                compressed_nsk.bootstrapping_key()
            } else {
                panic!("GPU only supports the Standard atomic pattern")
            };
        let bootstrapping_key = match compressed_bsk {
            CompressedShortint128BootstrappingKey::Classic {
                bsk: seeded_bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let std_bsk = seeded_bsk.as_view().par_decompress_into_lwe_bootstrap_key();

                let modulus_switch_noise_reduction_configuration =
                    match modulus_switch_noise_reduction_key {
                        CompressedModulusSwitchConfiguration::Standard => None,
                        CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            _modulus_switch_noise_reduction_key,
                        ) => panic!("Drift noise reduction is not supported on GPU"),
                        CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction => {
                            Some(CudaModulusSwitchNoiseReductionConfiguration::Centered)
                        }
                    };

                let bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
                    &std_bsk,
                    modulus_switch_noise_reduction_configuration,
                    streams,
                );
                CudaBootstrappingKey::Classic(bsk)
            }
            CompressedShortint128BootstrappingKey::MultiBit {
                bsk: seeded_mb_bsk,
                thread_count: _thread_count,
                deterministic_execution: _deterministic_execution,
            } => {
                let std_mb_bsk = seeded_mb_bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let mb_bsk = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                    &std_mb_bsk,
                    streams,
                );

                CudaBootstrappingKey::MultiBit(mb_bsk)
            }
        };

        CudaNoiseSquashingKey {
            bootstrapping_key,
            message_modulus: self.key.message_modulus(),
            carry_modulus: self.key.carry_modulus(),
            output_ciphertext_modulus: self.key.output_ciphertext_modulus(),
        }
    }
}
