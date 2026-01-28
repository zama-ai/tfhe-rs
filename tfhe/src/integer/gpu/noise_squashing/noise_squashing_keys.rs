use super::keys::CudaNoiseSquashingKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::keys::expanded::{
    ExpandedAtomicPatternNoiseSquashingKey, ExpandedNoiseSquashingKey,
};
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::noise_squashing::CompressedNoiseSquashingKey;

impl CudaNoiseSquashingKey {
    /// Creates a `CudaNoiseSquashingKey` from an expanded (standard domain) noise squashing key.
    ///
    /// This method converts an already-expanded noise squashing key (in standard domain)
    /// to GPU memory. Use this when you have an `ExpandedNoiseSquashingKey`
    /// from calling `expand()` on a compressed key.
    pub(crate) fn from_expanded_noise_squashing_key(
        expanded: &ExpandedNoiseSquashingKey,
        streams: &CudaStreams,
    ) -> Self {
        let expanded_bsk = match expanded.atomic_pattern() {
            ExpandedAtomicPatternNoiseSquashingKey::Standard(bsk) => bsk,
            ExpandedAtomicPatternNoiseSquashingKey::KeySwitch32(_) => {
                panic!("GPU only supports the Standard atomic pattern")
            }
        };

        let bootstrapping_key =
            CudaBootstrappingKey::from_expanded_bootstrapping_key(expanded_bsk, streams)
                .expect("Unsupported configuration");

        Self {
            bootstrapping_key,
            message_modulus: expanded.message_modulus(),
            carry_modulus: expanded.carry_modulus(),
            output_ciphertext_modulus: expanded.output_ciphertext_modulus(),
        }
    }
}

impl CompressedNoiseSquashingKey {
    pub fn decompress_to_cuda(&self, streams: &CudaStreams) -> CudaNoiseSquashingKey {
        let expanded = self.expand();

        CudaNoiseSquashingKey::from_expanded_noise_squashing_key(&expanded, streams)
    }
}
