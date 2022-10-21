use super::engine_error;

use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextDiscardingEncryptionError for LweCiphertextDiscardingEncryptionEngine @
    LweDimensionMismatch => "The secret key and ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, Ciphertext>(
        key: &SecretKey,
        output: &Ciphertext,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        Ciphertext: LweCiphertextEntity,
    {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the encryption of the `input` plaintext, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextEncryptionEngine`)
pub trait LweCiphertextDiscardingEncryptionEngine<SecretKey, Plaintext, Ciphertext>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity,
{
    /// Encrypts an LWE ciphertext.
    fn discard_encrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<(), LweCiphertextDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    );
}
