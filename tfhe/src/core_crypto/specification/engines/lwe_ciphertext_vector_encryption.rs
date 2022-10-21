use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorEncryptionError for LweCiphertextVectorEncryptionEngine @
}

/// A trait for engines encrypting LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext vector containing
/// the element-wise encryption of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextEncryptionEngine`)
pub trait LweCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Encrypts an LWE ciphertext vector.
    fn encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<CiphertextVector, LweCiphertextVectorEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> CiphertextVector;
}
