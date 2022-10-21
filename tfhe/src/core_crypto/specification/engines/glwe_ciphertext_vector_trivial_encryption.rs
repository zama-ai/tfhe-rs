use super::engine_error;
use crate::core_crypto::prelude::{GlweCiphertextCount, GlweSize, PlaintextVectorEntity};

use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GlweCiphertextVectorEntity;

engine_error! {
    GlweCiphertextVectorTrivialEncryptionError for GlweCiphertextVectorTrivialEncryptionEngine @
    PlaintextCountMismatch => "The number of ciphertexts must divide the \
    plaintext count of the input vector (the result of this division is the polynomial size)."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorTrivialEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<PlaintextVector>(
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        PlaintextVector: PlaintextVectorEntity,
    {
        if input.plaintext_count().0 % glwe_ciphertext_count.0 != 0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines trivially encrypting GLWE ciphertext vector.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext vector containing
/// the trivial encryption of the `input` plaintext vector with the requested `glwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait GlweCiphertextVectorTrivialEncryptionEngine<PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: GlweCiphertextVectorEntity,
{
    /// Trivially encrypts a plaintext vector into a GLWE ciphertext vector.
    fn trivially_encrypt_glwe_ciphertext_vector(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector,
    ) -> Result<CiphertextVector, GlweCiphertextVectorTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely trivially encrypts a plaintext vector into a GLWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector,
    ) -> CiphertextVector;
}
