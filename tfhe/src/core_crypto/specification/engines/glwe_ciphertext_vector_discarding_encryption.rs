use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextVectorDiscardingEncryptionError for GlweCiphertextVectorDiscardingEncryptionEngine @
    GlweDimensionMismatch => "The GLWE dimensions of the key and the output ciphertext vector must \
                              be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the output ciphertext vector \
                               must be the same.",
    PlaintextCountMismatch => "The input plaintext vector length and output ciphertext vector \
                               capacity (poly size * length) must be the same."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector, CiphertextVector>(
        key: &SecretKey,
        output: &CiphertextVector,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: GlweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
        CiphertextVector: GlweCiphertextVectorEntity,
    {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(Self::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(Self::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encrypting (discarding) GLWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext vector
/// with the piece-wise encryptions of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::GlweCiphertextEncryptionEngine`)
pub trait GlweCiphertextVectorDiscardingEncryptionEngine<
    SecretKey,
    PlaintextVector,
    CiphertextVector,
>: AbstractEngine where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: GlweCiphertextVectorEntity,
{
    /// Encrypts a GLWE ciphertext vector .
    fn discard_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a GLWE ciphertext vector .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    );
}
