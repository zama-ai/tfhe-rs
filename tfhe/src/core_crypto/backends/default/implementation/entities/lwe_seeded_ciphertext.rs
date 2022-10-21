use crate::core_crypto::commons::crypto::lwe::LweSeededCiphertext as ImplLweSeededCiphertext;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::LweDimension;
use crate::core_crypto::specification::entities::markers::LweSeededCiphertextKind;
use crate::core_crypto::specification::entities::{
    AbstractEntity, LweSeededCiphertextEntity,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a seeded LWE ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertext32(pub(crate) ImplLweSeededCiphertext<u32>);
impl AbstractEntity for LweSeededCiphertext32 {
    type Kind = LweSeededCiphertextKind;
}
impl LweSeededCiphertextEntity for LweSeededCiphertext32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a seeded LWE ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertext64(pub(crate) ImplLweSeededCiphertext<u64>);
impl AbstractEntity for LweSeededCiphertext64 {
    type Kind = LweSeededCiphertextKind;
}
impl LweSeededCiphertextEntity for LweSeededCiphertext64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
