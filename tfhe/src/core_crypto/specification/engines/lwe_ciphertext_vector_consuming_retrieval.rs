use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorConsumingRetrievalError for LweCiphertextVectorConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from an LWE ciphertext
/// vector consuming it in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// `input` LWE ciphertext vector consuming it in the process.
pub trait LweCiphertextVectorConsumingRetrievalEngine<CiphertextVector, Container>:
    AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Retrieves the content of the container from an LWE ciphertext vector, consuming it in the
    /// process.
    fn consume_retrieve_lwe_ciphertext_vector(
        &mut self,
        ciphertext: CiphertextVector,
    ) -> Result<Container, LweCiphertextVectorConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from an LWE ciphertext vector, consuming
    /// it in the process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorConsumingRetrievalError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn consume_retrieve_lwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext: CiphertextVector,
    ) -> Container;
}
