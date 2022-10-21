use super::engine_error;
use crate::core_crypto::prelude::LweSize;

use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextTrivialEncryptionError for LweCiphertextTrivialEncryptionEngine @
}

/// A trait for engines trivially encrypting LWE ciphertext.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates anLWE ciphertext containing the
/// trivial encryption of the `input` plaintext with the requested `lwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait LweCiphertextTrivialEncryptionEngine<Plaintext, Ciphertext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Trivially encrypts an LWE ciphertext.
    fn trivially_encrypt_lwe_ciphertext(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext,
    ) -> Result<Ciphertext, LweCiphertextTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely creates the trivial LWE encryption of the plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextTrivialEncryptionError ]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn trivially_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &Plaintext,
    ) -> Ciphertext;
}
