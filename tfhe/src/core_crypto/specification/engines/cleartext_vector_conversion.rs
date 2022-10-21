use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorConversionError for CleartextVectorConversionEngine @
}

/// A trait for engines converting (discard) cleartext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext vector containing the
/// conversion of the `input` cleartext vector to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait CleartextVectorConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextVectorEntity,
    Output: CleartextVectorEntity,
{
    /// Converts a cleartext vector.
    fn convert_cleartext_vector(
        &mut self,
        input: &Input,
    ) -> Result<Output, CleartextVectorConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_cleartext_vector_unchecked(&mut self, input: &Input) -> Output;
}
