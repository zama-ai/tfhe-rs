use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::CleartextEntity;

engine_error! {
    CleartextDiscardingRetrievalError for CleartextDiscardingRetrievalEngine @
}

/// A trait for engines retrieving (discarding) arbitrary values from cleartexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `value` arbitrary value with
/// the retrieval of the `input` cleartext. By arbitrary here, we mean that `Value` can be any type
/// that suits the backend implementor (an integer, a struct wrapping integers, a struct wrapping
/// foreign data or any other thing).
///
/// # Formal Definition
pub trait CleartextDiscardingRetrievalEngine<Cleartext, Value>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Retrieves an arbitrary value from a cleartext.
    fn discard_retrieve_cleartext(
        &mut self,
        value: &mut Value,
        input: &Cleartext,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves an arbitrary value from a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextDiscardingRetrievalError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn discard_retrieve_cleartext_unchecked(&mut self, value: &mut Value, input: &Cleartext);
}
