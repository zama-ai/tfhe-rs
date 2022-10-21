use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextRetrievalError for PlaintextRetrievalEngine @
}

/// A trait for engines retrieving arbitrary values from plaintexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an arbitrary value from the
/// `plaintext` plaintext. By arbitrary here, we mean that `Value` can be any type that suits the
/// backend implementor (an integer, a struct wrapping integers, a struct wrapping foreign data or
/// any other thing).
///
/// # Formal Definition
pub trait PlaintextRetrievalEngine<Plaintext, Value>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Retrieves an arbitrary value from a plaintext.
    fn retrieve_plaintext(
        &mut self,
        plaintext: &Plaintext,
    ) -> Result<Value, PlaintextRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves an arbitrary value from a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextRetrievalError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn retrieve_plaintext_unchecked(&mut self, plaintext: &Plaintext) -> Value;
}
