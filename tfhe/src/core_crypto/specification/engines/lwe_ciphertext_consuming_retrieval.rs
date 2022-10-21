use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextConsumingRetrievalError for LweCiphertextConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from an LWE ciphertext consuming it
/// in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// `input` LWE ciphertext consuming it in the process.
pub trait LweCiphertextConsumingRetrievalEngine<Ciphertext, Container>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    /// Retrieves the content of the container from an LWE ciphertext, consuming it in the process.
    fn consume_retrieve_lwe_ciphertext(
        &mut self,
        ciphertext: Ciphertext,
    ) -> Result<Container, LweCiphertextConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from an LWE ciphertext, consuming it in the
    /// process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextConsumingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn consume_retrieve_lwe_ciphertext_unchecked(
        &mut self,
        ciphertext: Ciphertext,
    ) -> Container;
}
