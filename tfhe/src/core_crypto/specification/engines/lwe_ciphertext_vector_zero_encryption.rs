use super::engine_error;
use crate::core_crypto::prelude::{LweCiphertextCount, Variance};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{LweCiphertextVectorEntity, LweSecretKeyEntity};

engine_error! {
    LweCiphertextVectorZeroEncryptionError for LweCiphertextVectorZeroEncryptionEngine @
    NullCiphertextCount => "The ciphertext count must be greater than zero."
}

impl<EngineError: std::error::Error> LweCiphertextVectorZeroEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(count: LweCiphertextCount) -> Result<(), Self> {
        if count.0 == 0 {
            return Err(Self::NullCiphertextCount);
        }
        Ok(())
    }
}

/// A trait for engines encrypting zero in LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext vector containing
/// encryptions of zeros, under the `key` secret key.
///
/// # Formal Definition
///
/// This generates a vector of [`LWE encryption`]
/// (`crate::core_crypto::specification::engines::LweCiphertextEncryptionEngine`) of zero.
pub trait LweCiphertextVectorZeroEncryptionEngine<SecretKey, CiphertextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Encrypts zeros in an LWE ciphertext vector.
    fn zero_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<CiphertextVector, LweCiphertextVectorZeroEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts zeros in an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorZeroEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn zero_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> CiphertextVector;
}
