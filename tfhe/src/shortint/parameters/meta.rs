use crate::shortint::parameters::{
    Backend, CompactPublicKeyEncryptionParameters, CompressionParameters,
    MetaNoiseSquashingParameters, ShortintKeySwitchingParameters,
};
use crate::shortint::AtomicPatternParameters;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DedicatedCompactPublicKeyParameters {
    /// Parameters used by the dedicated compact public key
    pub pke_params: CompactPublicKeyEncryptionParameters,
    /// Parameters used to key switch from the compact public key
    /// parameters to compute parameters
    pub ksk_params: ShortintKeySwitchingParameters,
    /// Parameters to key switch from the compact public key
    /// to rerand state
    pub re_randomization_parameters: Option<ShortintKeySwitchingParameters>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MetaParameters {
    pub backend: Backend,
    /// The parameters used by ciphertext when doing computations
    pub compute_parameters: AtomicPatternParameters,
    /// Parameters when using a dedicated compact public key
    /// (For smaller and more efficient CompactCiphertextList)
    pub dedicated_compact_public_key_parameters: Option<DedicatedCompactPublicKeyParameters>,
    /// Parameters for compression CompressedCiphertextList
    pub compression_parameters: Option<CompressionParameters>,
    /// Parameters for noise squashing
    pub noise_squashing_parameters: Option<MetaNoiseSquashingParameters>,
}
