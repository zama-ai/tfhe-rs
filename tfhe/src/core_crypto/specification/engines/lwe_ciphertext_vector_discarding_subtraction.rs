use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorDiscardingSubtractionError for LweCiphertextVectorDiscardingSubtractionEngine @
    LweDimensionMismatch => "The input and output LWE dimensions must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingSubtractionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<OutputCiphertextVector, InputCiphertextVector>(
        output: &OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputCiphertextVector,
    ) -> Result<(), Self>
    where
        InputCiphertextVector: LweCiphertextVectorEntity,
        OutputCiphertextVector: LweCiphertextVectorEntity,
    {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(Self::LweDimensionMismatch);
        }
        if output.lwe_ciphertext_count() != input_1.lwe_ciphertext_count()
            || output.lwe_ciphertext_count() != input_2.lwe_ciphertext_count()
        {
            return Err(Self::CiphertextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines subtracting (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise subtraction of the `input_2` LWE ciphertext vector to the `input_1` lwe
/// ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingSubtractionEngine<
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Subtracts two LWE ciphertext vectors.
    fn discard_sub_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorDiscardingSubtractionError<Self::EngineError>>;

    /// Unsafely subtracts two LWE ciphertext vectors.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingSubtractionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_sub_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputCiphertextVector,
    );
}
