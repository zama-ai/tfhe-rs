use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorDiscardingConversionError for CleartextVectorDiscardingConversionEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same"
}

impl<EngineError: std::error::Error> CleartextVectorDiscardingConversionError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Input, Output>(output: &Output, input: &Input) -> Result<(), Self>
    where
        Input: CleartextVectorEntity,
        Output: CleartextVectorEntity,
    {
        if output.cleartext_count() != input.cleartext_count() {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines converting (discarding) cleartexts vector.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` cleartext vector with
/// the conversion of the `input` cleartext vector to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextVectorDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextVectorEntity,
    Output: CleartextVectorEntity,
{
    /// Converts a cleartext vector .
    fn discard_convert_cleartext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), CleartextVectorDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_cleartext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
