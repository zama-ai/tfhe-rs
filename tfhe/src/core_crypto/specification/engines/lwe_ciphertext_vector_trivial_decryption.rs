use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, PlaintextVectorEntity,
};

use super::engine_error;

engine_error! {
    LweCiphertextVectorTrivialDecryptionError for LweCiphertextVectorTrivialDecryptionEngine @
}

/// A trait for engines trivially decrypting LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// trivial decryption of the `input` ciphertext vector.
///
/// # Formal Definition
///
/// see [here](../engines/trait.LweCiphertextVectorTrivialEncryptionEngine.html)
pub trait LweCiphertextVectorTrivialDecryptionEngine<CiphertextVector, PlaintextVector>:
    AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext vector into a plaintext vector.
    fn trivially_decrypt_lwe_ciphertext_vector(
        &mut self,
        input: &CiphertextVector,
    ) -> Result<PlaintextVector, LweCiphertextVectorTrivialDecryptionError<Self::EngineError>>;

    /// Unsafely trivially decrypts an LWE ciphertext vector into a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorTrivialDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &CiphertextVector,
    ) -> PlaintextVector;
}
