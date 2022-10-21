use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextDiscardingRetrievalError for PlaintextDiscardingRetrievalEngine @
}

/// A trait for engines retrieving (discarding) arbitrary values from plaintexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value with
/// the retrieval of the `input` plaintext value. By arbitrary here, we mean that `Value` can be any
/// type that suits the backend implementor (an integer, a struct wrapping integers, a struct
/// wrapping foreign data or any other thing).
///
/// # Formal Definition
pub trait PlaintextDiscardingRetrievalEngine<Plaintext, Value>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Retrieves an arbitrary value from a plaintext inplace.
    fn discard_retrieve_plaintext(
        &mut self,
        output: &mut Value,
        input: &Plaintext,
    ) -> Result<(), PlaintextDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves an arbitrary value from a plaintext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextDiscardingRetrievalError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn discard_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut Value,
        input: &Plaintext,
    );
}
