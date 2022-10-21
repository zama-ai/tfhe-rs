use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorCreationError for PlaintextVectorCreationEngine @
    EmptyInput => "The input slice must not be empty."
}

impl<EngineError: std::error::Error> PlaintextVectorCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<Value>(values: &[Value]) -> Result<(), Self> {
        if values.is_empty() {
            return Err(Self::EmptyInput);
        }
        Ok(())
    }
}

/// A trait for engines creating plaintext vectors from arbitrary values.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector from the `values`
/// slice of arbitrary values. By arbitrary here, we mean that `Value` can be any type that suits
/// the backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data
/// or any other thing).
///
/// # Formal Definition
pub trait PlaintextVectorCreationEngine<Value, PlaintextVector>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Creates a plaintext vector from a slice of arbitrary values.
    fn create_plaintext_vector_from(
        &mut self,
        values: &[Value],
    ) -> Result<PlaintextVector, PlaintextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates a plaintext vector from a slice of arbitrary values.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_plaintext_vector_from_unchecked(
        &mut self,
        values: &[Value],
    ) -> PlaintextVector;
}
