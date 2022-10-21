use super::engine_error;
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorDiscardingEncryptionError for LweCiphertextVectorDiscardingEncryptionEngine @
    LweDimensionMismatch => "The key and output LWE dimensions must be the same.",
    PlaintextCountMismatch => "The input plaintext count and the output ciphertext count must be \
                               the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingEncryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, PlaintextVector, CiphertextVector>(
        key: &SecretKey,
        output: &CiphertextVector,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        PlaintextVector: PlaintextVectorEntity,
        CiphertextVector: LweCiphertextVectorEntity,
    {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }

        Ok(())
    }
}

/// A trait for engines encrypting (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise encryption of the `input` plaintext vector under the `key` LWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextEncryptionEngine`)
pub trait LweCiphertextVectorDiscardingEncryptionEngine<
    SecretKey,
    PlaintextVector,
    CiphertextVector,
>: AbstractEngine where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Encrypts an LWE ciphertext vector.
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encryprs an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    );
}
