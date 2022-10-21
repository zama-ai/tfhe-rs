use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextEntity;

engine_error! {
    CleartextConversionError for CleartextConversionEngine @
}

/// A trait for engines converting cleartexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext containing the
/// conversion of the `input` cleartext to a type with a different representation (for instance from
/// cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextEntity,
    Output: CleartextEntity,
{
    /// Converts a cleartext.
    fn convert_cleartext(
        &mut self,
        input: &Input,
    ) -> Result<Output, CleartextConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_cleartext_unchecked(&mut self, input: &Input) -> Output;
}
