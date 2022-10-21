use crate::core_crypto::commons::crypto::lwe::LweList as ImplLweList;
use crate::core_crypto::prelude::{LweCiphertextCount, LweDimension};
use crate::core_crypto::specification::entities::markers::LweCiphertextVectorKind;
use crate::core_crypto::specification::entities::{
    AbstractEntity, LweCiphertextVectorEntity,
};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of LWE ciphertexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextVector32(pub(crate) ImplLweList<Vec<u32>>);

impl AbstractEntity for LweCiphertextVector32 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVector32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of LWE ciphertexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextVector64(pub(crate) ImplLweList<Vec<u64>>);

impl AbstractEntity for LweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVector64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweCiphertextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

// LweCiphertextVectorViews are just LweCiphertextVector entities that do not own their memory,
// they use a slice as a container as opposed to Vec for the standard LweCiphertextVector

/// A structure representing a vector of LWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextVectorView32<'a>(pub(crate) ImplLweList<&'a [u32]>);

impl AbstractEntity for LweCiphertextVectorView32<'_> {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVectorView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing a vector of LWE ciphertext views, with 32 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextVectorMutView32<'a>(pub(crate) ImplLweList<&'a mut [u32]>);

impl AbstractEntity for LweCiphertextVectorMutView32<'_> {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVectorMutView32<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing a vector of LWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but immutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Immutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextVectorView64<'a>(pub(crate) ImplLweList<&'a [u64]>);

impl AbstractEntity for LweCiphertextVectorView64<'_> {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVectorView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A structure representing a vector of LWE ciphertext views, with 64 bits of precision.
///
/// By _view_ here, we mean that the entity does not own the data, but mutably borrows it.
///
/// Notes:
/// ------
/// This view is not Clone as Clone for a slice is not defined. It is not Deserialize either,
/// as Deserialize of a slice is not defined. Mutable variant.
#[derive(Debug, PartialEq, Eq)]
pub struct LweCiphertextVectorMutView64<'a>(pub(crate) ImplLweList<&'a mut [u64]>);

impl AbstractEntity for LweCiphertextVectorMutView64<'_> {
    type Kind = LweCiphertextVectorKind;
}

impl LweCiphertextVectorEntity for LweCiphertextVectorMutView64<'_> {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}
