use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorDecryptionError for LweCiphertextVectorDecryptionEngine @
    LweDimensionMismatch => "The input and secret key LWE dimension must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextVector>(
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        CiphertextVector: LweCiphertextVectorEntity,
    {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing
/// the element-wise decryption of the `input` LWE ciphertext vector under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDecryptionEngine`)
pub trait LweCiphertextVectorDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts an LWE ciphertext vector.
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> Result<PlaintextVector, LweCiphertextVectorDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> PlaintextVector;
}
