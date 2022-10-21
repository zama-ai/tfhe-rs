use super::engine_error;

use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextDiscardingDecryptionError for LweCiphertextDiscardingDecryptionEngine @
    LweDimensionMismatch => "The secret key and ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, Ciphertext>(
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        Ciphertext: LweCiphertextEntity,
    {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext with the
/// decryption of the `input` LWE ciphertext, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDecryptionEngine`)
pub trait LweCiphertextDiscardingDecryptionEngine<SecretKey, Ciphertext, Plaintext>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Ciphertext: LweCiphertextEntity,
    Plaintext: PlaintextEntity,
{
    /// Decrypts an LWE ciphertext.
    fn discard_decrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Plaintext,
        input: &Ciphertext,
    ) -> Result<(), LweCiphertextDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Plaintext,
        input: &Ciphertext,
    );
}
