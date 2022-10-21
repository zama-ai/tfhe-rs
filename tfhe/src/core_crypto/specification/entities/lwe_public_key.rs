use crate::core_crypto::prelude::{LweDimension, LwePublicKeyZeroEncryptionCount};
use crate::core_crypto::specification::entities::markers::LwePublicKeyKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE public key.
///
/// # Formal Definition
///
/// ## LWE Public Key
///
/// An LWE public key contains $m$ LWE encryptions of 0 under a secret key
/// $\vec{s}\in\mathbb{Z}\_q^n$ where $n$ is the LWE dimension of the ciphertexts contained in the
/// public key.
pub trait LwePublicKeyEntity: AbstractEntity<Kind = LwePublicKeyKind> {
    /// Returns the LWE dimension of the key.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of LWE encryption of 0 in the key.
    fn lwe_zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount;
}
