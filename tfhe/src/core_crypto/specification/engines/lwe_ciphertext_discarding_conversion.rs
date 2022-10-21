use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextDiscardingConversionError for LweCiphertextDiscardingConversionEngine @
    LweDimensionMismatch => "All the ciphertext LWE dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: LweCiphertextEntity,
        Output: LweCiphertextEntity,
    {
        if input.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) LWE ciphertexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the conversion of the `input` LWE ciphertext to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweCiphertextDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextEntity,
    Output: LweCiphertextEntity,
{
    /// Converts a LWE ciphertext .
    fn discard_convert_lwe_ciphertext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCiphertextDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE ciphertext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
