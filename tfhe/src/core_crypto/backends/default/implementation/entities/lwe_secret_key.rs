use crate::core_crypto::commons::crypto::secret::LweSecretKey as ImpLweSecretKey;
use crate::core_crypto::prelude::{BinaryKeyKind, LweDimension};
use crate::core_crypto::specification::entities::markers::LweSecretKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LweSecretKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE secret key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSecretKey32(pub(crate) ImpLweSecretKey<BinaryKeyKind, Vec<u32>>);
impl AbstractEntity for LweSecretKey32 {
    type Kind = LweSecretKeyKind;
}
impl LweSecretKeyEntity for LweSecretKey32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSecretKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE secret key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweSecretKey64(pub(crate) ImpLweSecretKey<BinaryKeyKind, Vec<u64>>);
impl AbstractEntity for LweSecretKey64 {
    type Kind = LweSecretKeyKind;
}
impl LweSecretKeyEntity for LweSecretKey64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LweSecretKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
