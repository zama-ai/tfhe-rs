use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorDiscardingConversionError for LweCiphertextVectorDiscardingConversionEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextVectorDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: LweCiphertextVectorEntity,
        Output: LweCiphertextVectorEntity,
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

/// A trait for engines converting (discarding) LWE ciphertext vectors .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the conversion of the `input` LWE ciphertext vector to a type with a different
/// representation (for instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextVectorEntity,
    Output: LweCiphertextVectorEntity,
{
    /// Converts a LWE ciphertext vector .
    fn discard_convert_lwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCiphertextVectorDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE ciphertext vector .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
