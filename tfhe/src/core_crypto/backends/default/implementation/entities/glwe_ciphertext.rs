use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GlweCiphertextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a GLWE ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertext32(pub(crate) ImplGlweCiphertext<Vec<u32>>);

impl AbstractEntity for GlweCiphertext32 {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertext32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a GLWE ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertext64(pub(crate) ImplGlweCiphertext<Vec<u64>>);

impl AbstractEntity for GlweCiphertext64 {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertext64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

// GlweCiphertextViews are just GlweCiphertext entities that do not own their memory, they use a
// slice as a container as opposed to Vec for the standard GlweCiphertext

/// A structure representing a GLWE ciphertext view, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextView32<'a>(pub(crate) ImplGlweCiphertext<&'a [u32]>);
impl AbstractEntity for GlweCiphertextView32<'_> {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertextView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a GLWE ciphertext view, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextMutView32<'a>(pub(crate) ImplGlweCiphertext<&'a mut [u32]>);
impl AbstractEntity for GlweCiphertextMutView32<'_> {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertextMutView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a GLWE ciphertext view, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextView64<'a>(pub(crate) ImplGlweCiphertext<&'a [u64]>);

impl AbstractEntity for GlweCiphertextView64<'_> {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertextView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a GLWE ciphertext view, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextMutView64<'a>(pub(crate) ImplGlweCiphertext<&'a mut [u64]>);

impl AbstractEntity for GlweCiphertextMutView64<'_> {
    type Kind = GlweCiphertextKind;
}

impl GlweCiphertextEntity for GlweCiphertextMutView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
