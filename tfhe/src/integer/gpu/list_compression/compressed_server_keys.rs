use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::list_compression::server_keys::{
    CudaCompressionKey, CudaDecompressionKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey,
};
use crate::shortint::PBSParameters;

impl CompressedDecompressionKey {
    pub fn decompress_to_cuda(
        &self,
        parameters: PBSParameters,
        streams: &CudaStreams,
    ) -> CudaDecompressionKey {
        let h_bootstrap_key = self
            .blind_rotate_key
            .as_view()
            .par_decompress_into_lwe_bootstrap_key();

        let d_bootstrap_key =
            CudaLweBootstrapKey::from_lwe_bootstrap_key(&h_bootstrap_key, streams);

        let blind_rotate_key = CudaBootstrappingKey::Classic(d_bootstrap_key);

        CudaDecompressionKey {
            blind_rotate_key,
            lwe_per_glwe: self.lwe_per_glwe,
            parameters,
        }
    }
}

impl CompressedCompressionKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaCompressionKey {
        let packing_key_switching_key = self
            .packing_key_switching_key
            .as_view()
            .decompress_into_lwe_packing_keyswitch_key();

        let glwe_compression_key = CompressionKey {
            packing_key_switching_key,
            lwe_per_glwe: self.lwe_per_glwe,
            storage_log_modulus: self.storage_log_modulus,
        };

        CudaCompressionKey::from_compression_key(&glwe_compression_key, streams)
    }
}
