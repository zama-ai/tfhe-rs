use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextEntity;

engine_error! {
    CleartextCreationError for CleartextCreationEngine @
}

/// A trait for engines creating cleartexts from arbitrary values.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext from the `value`
/// arbitrary value. By arbitrary here, we mean that `Value` can be any type that suits the backend
/// implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or any other
/// thing).
///
/// # Formal Definition
pub trait CleartextCreationEngine<Value, Cleartext>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Creates a cleartext from an arbitrary value.
    fn create_cleartext_from(
        &mut self,
        value: &Value,
    ) -> Result<Cleartext, CleartextCreationError<Self::EngineError>>;

    /// Unsafely creates a cleartext from an arbitrary value.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextCreationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn create_cleartext_from_unchecked(&mut self, value: &Value) -> Cleartext;
}
