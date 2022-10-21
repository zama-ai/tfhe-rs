use crate::core_crypto::commons::crypto::secret::GlweSecretKey as ImpGlweSecretKey;
use crate::core_crypto::prelude::{BinaryKeyKind, GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweSecretKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GlweSecretKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a GLWE secret key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSecretKey32(pub(crate) ImpGlweSecretKey<BinaryKeyKind, Vec<u32>>);
impl AbstractEntity for GlweSecretKey32 {
    type Kind = GlweSecretKeyKind;
}
impl GlweSecretKeyEntity for GlweSecretKey32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSecretKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a GLWE secret key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweSecretKey64(pub(crate) ImpGlweSecretKey<BinaryKeyKind, Vec<u64>>);
impl AbstractEntity for GlweSecretKey64 {
    type Kind = GlweSecretKeyKind;
}
impl GlweSecretKeyEntity for GlweSecretKey64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweSecretKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
