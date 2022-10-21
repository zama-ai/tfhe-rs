use super::engine_error;
use crate::core_crypto::prelude::{GlweCiphertextCount, Variance};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity,
};

engine_error! {
    GlweCiphertextVectorZeroEncryptionError for GlweCiphertextVectorZeroEncryptionEngine @
    NullCiphertextCount => "The ciphertext count must be greater than zero."
}

impl<EngineError: std::error::Error> GlweCiphertextVectorZeroEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(count: GlweCiphertextCount) -> Result<(), Self> {
        if count.0 == 0 {
            return Err(Self::NullCiphertextCount);
        }
        Ok(())
    }
}

/// A trait for engines encrypting zero in GLWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE ciphertext vector containing
/// encryptions of zeros, under the `key` secret key.
///
/// # Formal Definition
///
/// This generates a vector of [`GLWE
/// encryption`](`crate::core_crypto::specification::engines::GlweCiphertextEncryptionEngine`) of
/// zero.
pub trait GlweCiphertextVectorZeroEncryptionEngine<SecretKey, CiphertextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextVector: GlweCiphertextVectorEntity,
{
    /// Encrypts zero in a GLWE ciphertext vector.
    fn zero_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<CiphertextVector, GlweCiphertextVectorZeroEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts zero in a GLWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorZeroEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn zero_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> CiphertextVector;
}
