use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, GlweDimension, PolynomialSize};
use crate::integer::compression_keys::{CompressedCompressionKey, CompressedDecompressionKey};
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
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
        let expanded = self.expand();

        CudaDecompressionKey::from_expanded_decompression_key(
            &expanded,
            glwe_dimension,
            polynomial_size,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
            streams,
        )
        .expect("Unsupported configuration")
    }
}

impl CompressedCompressionKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaCompressionKey {
        let compression_key = self.decompress();

        CudaCompressionKey::from_compression_key(&compression_key, streams)
    }
}
