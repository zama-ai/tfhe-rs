use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextVectorDecryptionError for GlweCiphertextVectorDecryptionEngine @
    GlweDimensionMismatch => "The key and input ciphertext vector GLWE dimension must be the same.",
    PolynomialSizeMismatch => "The key and input ciphertext vector polynomial size must be the \
                               same."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextVector>(
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        CiphertextVector: GlweCiphertextVectorEntity,
    {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting GLWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing
/// the piece-wise decryptions of the `input` GLWE ciphertext vector, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::GlweCiphertextDecryptionEngine`)
pub trait GlweCiphertextVectorDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextVector: GlweCiphertextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext vector.
    fn decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> Result<PlaintextVector, GlweCiphertextVectorDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a GLWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> PlaintextVector;
}
