use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextCreationError for PlaintextCreationEngine @
}

/// A trait for engines creating plaintexts from an arbitrary value.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext from the `value`
/// arbitrary value. By arbitrary here, we mean that `Value` can be any type that suits the backend
/// implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or any other
/// thing).
///
/// # Formal Definition
pub trait PlaintextCreationEngine<Value, Plaintext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Creates a plaintext from an arbitrary value.
    fn create_plaintext_from(
        &mut self,
        value: &Value,
    ) -> Result<Plaintext, PlaintextCreationError<Self::EngineError>>;

    /// Unsafely creates a plaintext from an arbitrary value.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextCreationError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn create_plaintext_from_unchecked(&mut self, value: &Value) -> Plaintext;
}
