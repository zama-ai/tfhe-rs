use super::engine_error;
use crate::core_crypto::prelude::LweSize;

use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorTrivialEncryptionError for LweCiphertextVectorTrivialEncryptionEngine @
}

/// A trait for engines trivially encrypting LWE ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext vector
/// containing the element-wise trivial encryption of the `input` plaintext vector,
/// with the requested `lwe_size`.
///
/// # Formal Definition
///
/// A trivial encryption uses a zero mask and no noise.
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the bootstrap.
pub trait LweCiphertextVectorTrivialEncryptionEngine<PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Trivially encrypts an LWE ciphertext vector.
    fn trivially_encrypt_lwe_ciphertext_vector(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector,
    ) -> Result<CiphertextVector, LweCiphertextVectorTrivialEncryptionError<Self::EngineError>>;

    /// Unsafely creates the trivial LWE encryption of the plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorTrivialEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn trivially_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector,
    ) -> CiphertextVector;
}
