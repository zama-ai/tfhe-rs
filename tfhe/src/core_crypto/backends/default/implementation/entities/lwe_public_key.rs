use crate::core_crypto::commons::crypto::lwe::LweList as ImpLwePublicKey;
use crate::core_crypto::prelude::{LweDimension, LwePublicKeyZeroEncryptionCount};
use crate::core_crypto::specification::entities::markers::LwePublicKeyKind;
use crate::core_crypto::specification::entities::{AbstractEntity, LwePublicKeyEntity};
#[cfg(feature = "backend_default_serialization")]
use serde::{Deserialize, Serialize};

/// A structure representing an LWE secret key with 32 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePublicKey32(pub(crate) ImpLwePublicKey<Vec<u32>>);
impl AbstractEntity for LwePublicKey32 {
    type Kind = LwePublicKeyKind;
}

impl LwePublicKeyEntity for LwePublicKey32 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LwePublicKey32Version {
    V0,
    #[serde(other)]
    Unsupported,
}

/// A structure representing an LWE secret key with 64 bits of precision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwePublicKey64(pub(crate) ImpLwePublicKey<Vec<u64>>);
impl AbstractEntity for LwePublicKey64 {
    type Kind = LwePublicKeyKind;
}
impl LwePublicKeyEntity for LwePublicKey64 {
    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.0.count().0)
    }
}

#[cfg(feature = "backend_default_serialization")]
#[derive(Serialize, Deserialize)]
pub(crate) enum LwePublicKey64Version {
    V0,
    #[serde(other)]
    Unsupported,
}
