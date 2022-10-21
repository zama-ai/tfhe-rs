use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextVectorDiscardingDecryptionError for GlweCiphertextVectorDiscardingDecryptionEngine @
    GlweDimensionMismatch => "The GLWE dimensions of the key and the input ciphertext vector must \
                              be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the input ciphertext vector must \
                               be the same.",
    PlaintextCountMismatch => "The input plaintext vector length and input ciphertext vector \
                               capacity (poly size * length) must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorDiscardingDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextVector, PlaintextVector>(
        key: &SecretKey,
        output: &PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        CiphertextVector: GlweCiphertextVectorEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0
            != (input.polynomial_size().0 * input.glwe_ciphertext_count().0)
        {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting (discarding) GLWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext vector  
/// with the piece-wise decryptions of the `input` GLWE ciphertext vector, under the `key` secret
/// key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::GlweCiphertextDecryptionEngine`)
pub trait GlweCiphertextVectorDiscardingDecryptionEngine<
    SecretKey,
    CiphertextVector,
    PlaintextVector,
>: AbstractEngine where
    SecretKey: GlweSecretKeyEntity,
    CiphertextVector: GlweCiphertextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext vector .
    fn discard_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), GlweCiphertextVectorDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext vector .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorDiscardingDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    );
}
