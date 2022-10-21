use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorFusingSubtractionError for LweCiphertextVectorFusingSubtractionEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output vectors length must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorFusingSubtractionError<EngineError> {
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

/// A trait for engines subtracting (fusing) LWE ciphertexts vectors.
///
/// # Semantics
///
/// This [fusing](super#operation-semantics) operation subtracts the `input` LWE ciphertext vector
/// to the `output` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorFusingSubtractionEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Subtracts two LWE ciphertext vectors.
    fn fuse_sub_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorFusingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts two LWE ciphertext vectors.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorFusingSubtractionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn fuse_sub_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
