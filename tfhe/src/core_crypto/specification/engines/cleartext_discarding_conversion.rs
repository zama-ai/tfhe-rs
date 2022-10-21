use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextEntity;

engine_error! {
    CleartextDiscardingConversionError for CleartextDiscardingConversionEngine @
}

/// A trait for engines converting (discarding) cleartexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` cleartext with the
/// conversion of the `input` cleartext to a type with a different representation (for instance from
/// cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextEntity,
    Output: CleartextEntity,
{
    /// Converts a cleartext .
    fn discard_convert_cleartext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), CleartextDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextDiscardingConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_convert_cleartext_unchecked(&mut self, output: &mut Output, input: &Input);
}
