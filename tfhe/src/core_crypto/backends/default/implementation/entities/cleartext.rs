use crate::core_crypto::commons::crypto::encoding::Cleartext as ImplCleartext;
use crate::core_crypto::specification::entities::markers::CleartextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, CleartextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a cleartext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleartext32(pub(crate) ImplCleartext<u32>);
impl AbstractEntity for Cleartext32 {
    type Kind = CleartextKind;
}
impl CleartextEntity for Cleartext32 {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum Cleartext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a cleartext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleartext64(pub(crate) ImplCleartext<u64>);
impl AbstractEntity for Cleartext64 {
    type Kind = CleartextKind;
}
impl CleartextEntity for Cleartext64 {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum Cleartext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a floating point cleartext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct CleartextF64(pub(crate) ImplCleartext<f64>);
impl AbstractEntity for CleartextF64 {
    type Kind = CleartextKind;
}
impl CleartextEntity for CleartextF64 {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum CleartextF64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
