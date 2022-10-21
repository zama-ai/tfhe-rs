use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, PlaintextEntity};

use super::engine_error;

engine_error! {
    LweCiphertextTrivialDecryptionError for LweCiphertextTrivialDecryptionEngine @
}

/// A trait for engines trivially decrypting LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext containing the
/// trivial decryption of the `input` ciphertext.
///
/// # Formal Definition
///
/// see [here](../engines/trait.LweCiphertextTrivialEncryptionEngine.html)
pub trait LweCiphertextTrivialDecryptionEngine<Ciphertext, Plaintext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    Plaintext: PlaintextEntity,
{
    /// Decrypts an LWE ciphertext vector into a plaintext vector.
    fn trivially_decrypt_lwe_ciphertext(
        &mut self,
        input: &Ciphertext,
    ) -> Result<Plaintext, LweCiphertextTrivialDecryptionError<Self::EngineError>>;

    /// Unsafely trivially decrypts an LWE ciphertext into a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextTrivialDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        input: &Ciphertext,
    ) -> Plaintext;
}
