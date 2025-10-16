use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, GlweDimension, PolynomialSize};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey,
};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
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
        match &self.key {
            crate::shortint::list_compression::CompressedDecompressionKey::Classic {
                blind_rotate_key,
                lwe_per_glwe,
            } => {
                let h_bootstrap_key = blind_rotate_key
                    .as_view()
                    .par_decompress_into_lwe_bootstrap_key();

                let d_bootstrap_key =
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(&h_bootstrap_key, None, streams);

                let blind_rotate_key = CudaBootstrappingKey::Classic(d_bootstrap_key);

                CudaDecompressionKey {
                    blind_rotate_key,
                    lwe_per_glwe: *lwe_per_glwe,
                    glwe_dimension,
                    polynomial_size,
                    message_modulus,
                    carry_modulus,
                    ciphertext_modulus,
                }
            }
            crate::shortint::list_compression::CompressedDecompressionKey::MultiBit { .. } => {
                todo!()
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
