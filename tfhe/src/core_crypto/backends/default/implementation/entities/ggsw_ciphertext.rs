use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext as ImplStandardGgswCiphertext;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::specification::entities::markers::GgswCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GgswCiphertextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a GGSW ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgswCiphertext32(pub(crate) ImplStandardGgswCiphertext<Vec<u32>>);
impl AbstractEntity for GgswCiphertext32 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for GgswCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GgswCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a GGSW ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgswCiphertext64(pub(crate) ImplStandardGgswCiphertext<Vec<u64>>);
impl AbstractEntity for GgswCiphertext64 {
    type Kind = GgswCiphertextKind;
}
impl GgswCiphertextEntity for GgswCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_level_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GgswCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
