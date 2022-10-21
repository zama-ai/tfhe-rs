use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorConversionError for PlaintextVectorConversionEngine @
}

/// A trait for engines converting plaintext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// conversion of the `input` plaintext vector to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait PlaintextVectorConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextVectorEntity,
    Output: PlaintextVectorEntity,
{
    /// Converts a plaintext vector.
    fn convert_plaintext_vector(
        &mut self,
        input: &Input,
    ) -> Result<Output, PlaintextVectorConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_plaintext_vector_unchecked(&mut self, input: &Input) -> Output;
}
