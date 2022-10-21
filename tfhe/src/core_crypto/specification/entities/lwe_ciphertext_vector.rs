use crate::core_crypto::prelude::{LweCiphertextCount, LweDimension};
use crate::core_crypto::specification::entities::markers::LweCiphertextVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an LWE ciphertext vector.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LweCiphertextEntity`)
pub trait LweCiphertextVectorEntity: AbstractEntity<Kind = LweCiphertextVectorKind> {
    /// Returns the LWE dimension of the ciphertexts.
    fn lwe_dimension(&self) -> LweDimension;

    /// Returns the number of ciphertexts contained in the vector.
    fn lwe_ciphertext_count(&self) -> LweCiphertextCount;
}
