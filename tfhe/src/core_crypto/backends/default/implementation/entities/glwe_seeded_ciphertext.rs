use crate::core_crypto::commons::crypto::glwe::GlweSeededCiphertext as ImplGlweSeededCiphertext;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweSeededCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GlweSeededCiphertextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a seeded GLWE ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertext32(pub(crate) ImplGlweSeededCiphertext<Vec<u32>>);
impl AbstractEntity for GlweSeededCiphertext32 {
    type Kind = GlweSeededCiphertextKind;
}
impl GlweSeededCiphertextEntity for GlweSeededCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a seeded GLWE ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSeededCiphertext64(pub(crate) ImplGlweSeededCiphertext<Vec<u64>>);
impl AbstractEntity for GlweSeededCiphertext64 {
    type Kind = GlweSeededCiphertextKind;
}
impl GlweSeededCiphertextEntity for GlweSeededCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn compression_seed(&self) -> CompressionSeed {
        self.0.compression_seed()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSeededCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
