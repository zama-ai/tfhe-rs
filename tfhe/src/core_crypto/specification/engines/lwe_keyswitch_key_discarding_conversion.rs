use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyDiscardingConversionError for LweKeyswitchKeyDiscardingConversionEngine @
    InputLweDimensionMismatch => "The two keys must have the same input LWE dimension.",
    OutputLweDimensionMismatch => "The two keys must have the same output LWE dimension.",
    DecompositionBaseLogMismatch => "The two keys must have the same base logarithms.",
    DecompositionLevelCountMismatch => "The two keys must have the same level counts."
}

impl<EngineError: std::error::Error> LweKeyswitchKeyDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: LweKeyswitchKeyEntity,
        Output: LweKeyswitchKeyEntity,
    {
        if input.input_lwe_dimension() != output.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }

        if input.output_lwe_dimension() != output.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }

        if input.decomposition_base_log() != output.decomposition_base_log() {
            return Err(Self::DecompositionBaseLogMismatch);
        }

        if input.decomposition_level_count() != output.decomposition_level_count() {
            return Err(Self::DecompositionLevelCountMismatch);
        }

        Ok(())
    }
}

/// A trait for engines converting (discarding) LWE keyswitch keys .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE keyswitch key with
/// the conversion of the `input` LWE keyswitch key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweKeyswitchKeyDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweKeyswitchKeyEntity,
    Output: LweKeyswitchKeyEntity,
{
    /// Converts a LWE keyswitch key .
    fn discard_convert_lwe_keyswitch_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweKeyswitchKeyDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE keyswitch key .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_lwe_keyswitch_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
