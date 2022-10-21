use crate::core_crypto::commons::crypto::lwe::LweSeededList as ImplLweSeededList;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{LweCiphertextCount, LweDimension};
use crate::core_crypto::specification::entities::markers::LweSeededCiphertextVectorKind;
use crate::core_crypto::specification::entities::{
    AbstractEntity, LweSeededCiphertextVectorEntity,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of seeded LWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertextVector32(pub(crate) ImplLweSeededList<Vec<u32>>);

impl AbstractEntity for LweSeededCiphertextVector32 {
    type Kind = LweSeededCiphertextVectorKind;
}

impl LweSeededCiphertextVectorEntity for LweSeededCiphertextVector32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.get_compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of seeded LWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSeededCiphertextVector64(pub(crate) ImplLweSeededList<Vec<u64>>);

impl AbstractEntity for LweSeededCiphertextVector64 {
    type Kind = LweSeededCiphertextVectorKind;
}

impl LweSeededCiphertextVectorEntity for LweSeededCiphertextVector64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.get_compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSeededCiphertextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
