use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorRetrievalError for CleartextVectorRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from cleartext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of arbitrary values from the
/// `input` cleartext vector. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait CleartextVectorRetrievalEngine<CleartextVector, Value>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Retrieves arbitrary values from a cleartext vector.
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector,
    ) -> Result<Vec<Value>, CleartextVectorRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a cleartext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector,
    ) -> Vec<Value>;
}
