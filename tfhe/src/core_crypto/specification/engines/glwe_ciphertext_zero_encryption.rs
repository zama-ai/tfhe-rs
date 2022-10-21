use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{GlweCiphertextEntity, GlweSecretKeyEntity};

engine_error! {
    GlweCiphertextZeroEncryptionError for GlweCiphertextZeroEncryptionEngine @
}

/// A trait for engines encrypting zeros in GLWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext containing an
/// encryption of zeros, under the `key` secret key.
///
/// # Formal Definition
///
/// This generates a [`GLWE
/// encryption`](`crate::core_crypto::specification::engines::GlweCiphertextEncryptionEngine`) of
/// zero.
pub trait GlweCiphertextZeroEncryptionEngine<SecretKey, Ciphertext>: AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity,
{
    /// Encrypts a zero in a GLWE ciphertext.
    fn zero_encrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        noise: Variance,
    ) -> Result<Ciphertext, GlweCiphertextZeroEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a zero in a GLWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextZeroEncryptionError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn zero_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        noise: Variance,
    ) -> Ciphertext;
}
