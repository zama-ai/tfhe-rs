use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::prelude::PlaintextCount;
use crate::core_crypto::specification::entities::markers::PlaintextVectorKind;
use crate::core_crypto::specification::entities::{AbstractEntity, PlaintextVectorEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of plaintexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextVector32(pub(crate) ImplPlaintextList<Vec<u32>>);
impl AbstractEntity for PlaintextVector32 {
    type Kind = PlaintextVectorKind;
}
impl PlaintextVectorEntity for PlaintextVector32 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PlaintextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of plaintexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextVector64(pub(crate) ImplPlaintextList<Vec<u64>>);
impl AbstractEntity for PlaintextVector64 {
    type Kind = PlaintextVectorKind;
}
impl PlaintextVectorEntity for PlaintextVector64 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum PlaintextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
