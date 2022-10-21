use crate::core_crypto::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use crate::core_crypto::specification::entities::markers::GlweCiphertextVectorKind;
use crate::core_crypto::specification::entities::{AbstractEntity, GlweCiphertextVectorEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of GLWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextVector32(pub(crate) ImplGlweList<Vec<u32>>);
impl AbstractEntity for GlweCiphertextVector32 {
    type Kind = GlweCiphertextVectorKind;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector32 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of GLWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlweCiphertextVector64(pub(crate) ImplGlweList<Vec<u64>>);
impl AbstractEntity for GlweCiphertextVector64 {
    type Kind = GlweCiphertextVectorKind;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector64 {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum GlweCiphertextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

// GlweCiphertextVectorViews are just GlweCiphertextVector entities that do not own their memory,
// they use a slice as a container as opposed to Vec for the standard GlweCiphertextVector

/// A structure representing a vector of GLWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextVectorView32<'a>(pub(crate) ImplGlweList<&'a [u32]>);

impl AbstractEntity for GlweCiphertextVectorView32<'_> {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for GlweCiphertextVectorView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a vector of GLWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextVectorMutView32<'a>(pub(crate) ImplGlweList<&'a mut [u32]>);

impl AbstractEntity for GlweCiphertextVectorMutView32<'_> {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for GlweCiphertextVectorMutView32<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a vector of GLWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextVectorView64<'a>(pub(crate) ImplGlweList<&'a [u64]>);

impl AbstractEntity for GlweCiphertextVectorView64<'_> {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for GlweCiphertextVectorView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

/// A structure representing a vector of GLWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct GlweCiphertextVectorMutView64<'a>(pub(crate) ImplGlweList<&'a mut [u64]>);

impl AbstractEntity for GlweCiphertextVectorMutView64<'_> {
    type Kind = GlweCiphertextVectorKind;
}

impl GlweCiphertextVectorEntity for GlweCiphertextVectorMutView64<'_> {
    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
