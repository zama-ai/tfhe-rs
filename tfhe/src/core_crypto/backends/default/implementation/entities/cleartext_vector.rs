use crate::core_crypto::commons::crypto::encoding::CleartextList as ImplCleartextList;
use crate::core_crypto::prelude::CleartextCount;
use crate::core_crypto::specification::entities::markers::CleartextVectorKind;
use crate::core_crypto::specification::entities::{AbstractEntity, CleartextVectorEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a vector of cleartexts with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextVector32(pub(crate) ImplCleartextList<Vec<u32>>);
impl AbstractEntity for CleartextVector32 {
    type Kind = CleartextVectorKind;
}
impl CleartextVectorEntity for CleartextVector32 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextVector32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector of cleartexts with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextVector64(pub(crate) ImplCleartextList<Vec<u64>>);
impl AbstractEntity for CleartextVector64 {
    type Kind = CleartextVectorKind;
}
impl CleartextVectorEntity for CleartextVector64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextVector64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a vector floating point cleartext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct CleartextVectorF64(pub(crate) ImplCleartextList<Vec<f64>>);
impl AbstractEntity for CleartextVectorF64 {
    type Kind = CleartextVectorKind;
}
impl CleartextVectorEntity for CleartextVectorF64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextVectorF64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
