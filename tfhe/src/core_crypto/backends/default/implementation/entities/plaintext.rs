use crate::core_crypto::commons::crypto::encoding::Plaintext as ImplPlaintext;
use crate::core_crypto::specification::entities::markers::PlaintextKind;
use crate::core_crypto::specification::entities::{AbstractEntity, PlaintextEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing a plaintext with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plaintext32(pub(crate) ImplPlaintext<u32>);
impl AbstractEntity for Plaintext32 {
    type Kind = PlaintextKind;
}
impl PlaintextEntity for Plaintext32 {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum Plaintext32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing a plaintext with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plaintext64(pub(crate) ImplPlaintext<u64>);
impl AbstractEntity for Plaintext64 {
    type Kind = PlaintextKind;
}
impl PlaintextEntity for Plaintext64 {}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum Plaintext64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
