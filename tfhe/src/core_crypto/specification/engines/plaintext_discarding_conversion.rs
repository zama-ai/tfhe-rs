use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextDiscardingConversionError for PlaintextDiscardingConversionEngine @
}

/// A trait for engines converting (discarding) plaintexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext with the
/// conversion of the `input` plaintext to a type with a different representation (for instance from
/// cpu to gpu memory).
///
/// # Formal Definition
pub trait PlaintextDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextEntity,
    Output: PlaintextEntity,
{
    /// Converts a plaintext .
    fn discard_convert_plaintext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), PlaintextDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextDiscardingConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_convert_plaintext_unchecked(&mut self, output: &mut Output, input: &Input);
}
