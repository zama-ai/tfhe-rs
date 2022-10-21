use crate::core_crypto::commons::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::core_crypto::prelude::LweDimension;
use crate::core_crypto::specification::entities::markers::LweCiphertextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweCiphertextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE ciphertext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertext32(pub(crate) ImplLweCiphertext<Vec<u32>>);
impl AbstractEntity for LweCiphertext32 {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertext32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE ciphertext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertext64(pub(crate) ImplLweCiphertext<Vec<u64>>);
impl AbstractEntity for LweCiphertext64 {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertext64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

// LweCiphertextViews are just LweCiphertext entities that do not own their memory, they use a slice
// as a container as opposed to Vec for the standard LweCiphertext

/// A structure representing an LWE ciphertext view, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextView32<'a>(pub(crate) ImplLweCiphertext<&'a [u32]>);

impl AbstractEntity for LweCiphertextView32<'_> {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertextView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// A structure representing an LWE ciphertext view, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextMutView32<'a>(pub(crate) ImplLweCiphertext<&'a mut [u32]>);

impl AbstractEntity for LweCiphertextMutView32<'_> {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertextMutView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// A structure representing an LWE ciphertext view, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextView64<'a>(pub(crate) ImplLweCiphertext<&'a [u64]>);

impl AbstractEntity for LweCiphertextView64<'_> {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertextView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// A structure representing an LWE ciphertext view, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextMutView64<'a>(pub(crate) ImplLweCiphertext<&'a mut [u64]>);

impl AbstractEntity for LweCiphertextMutView64<'_> {
    type Kind = LweCiphertextKind;
}
impl LweCiphertextEntity for LweCiphertextMutView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}
