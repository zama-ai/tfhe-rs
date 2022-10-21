use crate::core_crypto::commons::crypto::glwe::GlweSeededList as ImplGlweSeededList;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweSeededCiphertextVectorKind;
use crate::core_crypto::specification::entities::{
    AbstractEntity, GlweSeededCiphertextVectorEntity,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of GLWE seeded ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertextVector32(pub(crate) ImplGlweSeededList<Vec<u32>>);
impl AbstractEntity for GlweSeededCiphertextVector32 {
    type Kind = GlweSeededCiphertextVectorKind;
}
impl GlweSeededCiphertextVectorEntity for GlweSeededCiphertextVector32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of GLWE seeded ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertextVector64(pub(crate) ImplGlweSeededList<Vec<u64>>);
impl AbstractEntity for GlweSeededCiphertextVector64 {
    type Kind = GlweSeededCiphertextVectorKind;
}
impl GlweSeededCiphertextVectorEntity for GlweSeededCiphertextVector64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
