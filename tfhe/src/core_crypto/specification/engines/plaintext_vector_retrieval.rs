use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorRetrievalError for PlaintextVectorRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from plaintext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of arbitrary values from the
/// `input` plaintext vector. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait PlaintextVectorRetrievalEngine<PlaintextVector, Value>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Retrieves arbitrary values from a plaintext vector.
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector,
    ) -> Result<Vec<Value>, PlaintextVectorRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector,
    ) -> Vec<Value>;
}
