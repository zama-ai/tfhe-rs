use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorDiscardingRetrievalError for CleartextVectorDiscardingRetrievalEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same."
}

impl<EngineError: std::error::Error> CleartextVectorDiscardingRetrievalError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value, CleartextVector>(
        output: &[Value],
        input: &CleartextVector,
    ) -> Result<(), Self>
    where
        CleartextVector: CleartextVectorEntity,
    {
        if output.len() != input.cleartext_count().0 {
            return Err(Self::CleartextCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines retrieving (discarding) arbitrary values from cleartext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value slice
/// with the element-wise retrieval of the `input` cleartext vector values. By arbitrary here, we
/// mean that `Value` can be any type that suits the backend implementor (an integer, a struct
/// wrapping integers, a struct wrapping foreign data or any other thing).
///
/// # Formal Definition
pub trait CleartextVectorDiscardingRetrievalEngine<CleartextVector, Value>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Retrieves arbitrary values from a cleartext vector.
    fn discard_retrieve_cleartext_vector(
        &mut self,
        output: &mut [Value],
        input: &CleartextVector,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a cleartext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorDiscardingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [Value],
        input: &CleartextVector,
    );
}
