use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorDiscardingOppositeError for LweCiphertextVectorDiscardingOppositeEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingOppositeError<EngineError> {
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

/// A trait for engines computing the opposite (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise opposite of the `input` LWE ciphertext vector.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::engines::LweCiphertextDiscardingOppositeEngine`)
pub trait LweCiphertextVectorDiscardingOppositeEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity,
{
    /// Computes the opposite of an LWE ciphertext vector.
    fn discard_opp_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorDiscardingOppositeError<Self::EngineError>>;

    /// Unsafely computes the opposite of an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingOppositeError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_opp_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
