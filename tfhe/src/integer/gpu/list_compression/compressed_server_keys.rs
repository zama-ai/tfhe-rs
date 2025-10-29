use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, GlweDimension, PolynomialSize};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ShortintCompressedBootstrappingKey,
};
use crate::shortint::{CarryModulus, MessageModulus};

impl CompressedDecompressionKey {
    pub fn decompress_to_cuda(
        &self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        ciphertext_modulus: CiphertextModulus<u64>,
        streams: &CudaStreams,
    ) -> CudaDecompressionKey {
        let crate::shortint::list_compression::CompressedDecompressionKey {
            ref bsk,
            lwe_per_glwe,
        } = self.key;

        match bsk {
            ShortintCompressedBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                assert_eq!(
                    modulus_switch_noise_reduction_key,
                    &CompressedModulusSwitchConfiguration::Standard
                );

                let h_bootstrap_key = bsk.as_view().par_decompress_into_lwe_bootstrap_key();

                let d_bootstrap_key =
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(&h_bootstrap_key, None, streams);

                let blind_rotate_key = CudaBootstrappingKey::Classic(d_bootstrap_key);

                CudaDecompressionKey {
                    blind_rotate_key,
                    lwe_per_glwe,
                    glwe_dimension,
                    polynomial_size,
                    message_modulus,
                    carry_modulus,
                    ciphertext_modulus,
                }
            }
            ShortintCompressedBootstrappingKey::MultiBit {
                seeded_bsk,
                deterministic_execution: _,
            } => {
                let h_bootstrap_key = seeded_bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let d_bootstrap_key = CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(
                    &h_bootstrap_key,
                    streams,
                );

                let blind_rotate_key = CudaBootstrappingKey::MultiBit(d_bootstrap_key);

                CudaDecompressionKey {
                    blind_rotate_key,
                    lwe_per_glwe,
                    glwe_dimension,
                    polynomial_size,
                    message_modulus,
                    carry_modulus,
                    ciphertext_modulus,
                }
            }
        }
    }
}

impl CompressedCompressionKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaCompressionKey {
        let packing_key_switching_key = self
            .key
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        let glwe_compression_key = CompressionKey {
            key: crate::shortint::list_compression::CompressionKey {
                packing_key_switching_key,
                lwe_per_glwe: self.key.lwe_per_glwe,
                storage_log_modulus: self.key.storage_log_modulus,
            },
        };

        CudaCompressionKey::from_compression_key(&glwe_compression_key, streams)
    }
}
