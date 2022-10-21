use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextConversionError for PlaintextConversionEngine @
}

/// A trait for engines converting plaintexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext containing the
/// conversion of the `input` plaintext to a type with a different representation (for instance from
/// cpu to gpu memory).
///
/// # Formal Definition
pub trait PlaintextConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextEntity,
    Output: PlaintextEntity,
{
    /// Converts a plaintext.
    fn convert_plaintext(
        &mut self,
        input: &Input,
    ) -> Result<Output, PlaintextConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_plaintext_unchecked(&mut self, input: &Input) -> Output;
}
