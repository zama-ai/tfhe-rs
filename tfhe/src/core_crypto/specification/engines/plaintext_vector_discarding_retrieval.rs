use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorDiscardingRetrievalError for PlaintextVectorDiscardingRetrievalEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same."
}

impl<EngineError: std::error::Error> PlaintextVectorDiscardingRetrievalError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value, PlaintextVector>(
        output: &[Value],
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        PlaintextVector: PlaintextVectorEntity,
    {
        if output.len() != input.plaintext_count().0 {
            return Err(Self::PlaintextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines retrieving (discarding) arbitrary values from plaintext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value slice
/// with the element-wise retrieval of the `input` plaintext vector values. By arbitrary here, we
/// mean that `Value` can be any type that suits the backend implementor (an integer, a struct
/// wrapping integers, a struct wrapping foreign data or any other
/// thing).
///
/// # Formal Definition
pub trait PlaintextVectorDiscardingRetrievalEngine<PlaintextVector, Value>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Retrieves arbitrary values from a plaintext vector.
    fn discard_retrieve_plaintext_vector(
        &mut self,
        output: &mut [Value],
        input: &PlaintextVector,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorDiscardingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [Value],
        input: &PlaintextVector,
    );
}
