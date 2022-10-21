use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{GlweCiphertextEntity, PlaintextVectorEntity};

engine_error! {
    GlweCiphertextTrivialDecryptionError for GlweCiphertextTrivialDecryptionEngine @
}

/// A trait for engines trivially decrypting GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// trivial decryption of the `input` ciphertext.
///
/// # Formal Definition
///
/// see [here](../engines/trait.GlweCiphertextTrivialEncryptionEngine.html)
pub trait GlweCiphertextTrivialDecryptionEngine<Ciphertext, PlaintextVector>:
    AbstractEngine
where
    Ciphertext: GlweCiphertextEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext into a plaintext vector.
    fn trivially_decrypt_glwe_ciphertext(
        &mut self,
        input: &Ciphertext,
    ) -> Result<PlaintextVector, GlweCiphertextTrivialDecryptionError<Self::EngineError>>;

    /// Unsafely trivially decrypts a GLWE ciphertext into a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextTrivialDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn trivially_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        input: &Ciphertext,
    ) -> PlaintextVector;
}
