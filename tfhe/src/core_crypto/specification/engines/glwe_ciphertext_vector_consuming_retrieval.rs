use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GlweCiphertextVectorEntity;

engine_error! {
    GlweCiphertextVectorConsumingRetrievalError for GlweCiphertextVectorConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from a GLWE ciphertext
/// vector consuming it in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// `input` GLWE ciphertext vector consuming it in the process.
pub trait GlweCiphertextVectorConsumingRetrievalEngine<CiphertextVector, Container>:
    AbstractEngine
where
    CiphertextVector: GlweCiphertextVectorEntity,
{
    /// Retrieves the content of the container from a GLWE ciphertext vector, consuming it in the
    /// process.
    fn consume_retrieve_glwe_ciphertext_vector(
        &mut self,
        ciphertext_vector: CiphertextVector,
    ) -> Result<Container, GlweCiphertextVectorConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from a GLWE ciphertext vector, consuming
    /// it in the process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorConsumingRetrievalError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn consume_retrieve_glwe_ciphertext_vector_unchecked(
        &mut self,
        ciphertext_vector: CiphertextVector,
    ) -> Container;
}
