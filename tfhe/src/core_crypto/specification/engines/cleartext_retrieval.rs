use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextEntity;

engine_error! {
    CleartextRetrievalError for CleartextRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from cleartexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an arbitrary value from the
/// `cleartext` cleartext. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait CleartextRetrievalEngine<Cleartext, Value>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Retrieves an arbitrary value from a cleartext.
    fn retrieve_cleartext(
        &mut self,
        cleartext: &Cleartext,
    ) -> Result<Value, CleartextRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves an arbitrary value from a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextRetrievalError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn retrieve_cleartext_unchecked(&mut self, cleartext: &Cleartext) -> Value;
}
