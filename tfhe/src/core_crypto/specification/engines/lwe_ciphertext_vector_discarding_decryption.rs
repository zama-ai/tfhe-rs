use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorDiscardingDecryptionError for LweCiphertextVectorDiscardingDecryptionEngine @
    LweDimensionMismatch => "The key and output LWE dimensions must be the same.",
    PlaintextCountMismatch => "The output plaintext count and the input ciphertext count must be \
                               the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingDecryptionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<SecretKey, CiphertextVector, PlaintextVector>(
        key: &SecretKey,
        output: &PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), Self>
    where
        SecretKey: LweSecretKeyEntity,
        CiphertextVector: LweCiphertextVectorEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if input.lwe_ciphertext_count().0 != output.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines decrypting (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext vector
/// with the element-wise decryption of the `input` LWE ciphertext vector under the `key` LWE secret
/// key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDecryptionEngine`)
pub trait LweCiphertextVectorDiscardingDecryptionEngine<
    SecretKey,
    CiphertextVector,
    PlaintextVector,
>: AbstractEngine where
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts an LWE ciphertext vector.
    fn discard_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), LweCiphertextVectorDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    );
}
