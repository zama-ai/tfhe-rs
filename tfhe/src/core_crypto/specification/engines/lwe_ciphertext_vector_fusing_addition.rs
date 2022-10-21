use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorFusingAdditionError for LweCiphertextVectorFusingAdditionEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output vectors length must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorFusingAdditionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertextVector, OutputCiphertextVector>(
        output: &OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), Self>
    where
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if input.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        if input.lwe_ciphertext_count() != output.lwe_ciphertext_count() {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines adding (fusing) LWE ciphertexts vectors.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation adds the `input` LWE ciphertext vector to
/// the `output` LWE ciphertext vector.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDiscardingAdditionEngine`)
pub trait LweCiphertextVectorFusingAdditionEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Add two LWE ciphertext vectors.
    fn fuse_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorFusingAdditionError<Self::EngineError>>;

    /// Unsafely add two LWE ciphertext vectors.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorFusingAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
