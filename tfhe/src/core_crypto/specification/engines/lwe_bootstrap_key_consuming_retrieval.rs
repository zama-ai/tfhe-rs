use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyConsumingRetrievalError for LweBootstrapKeyConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from an LWE bootstrap key consuming
/// it in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// input LWE bootstrap key consuming it in the process.
pub trait LweBootstrapKeyConsumingRetrievalEngine<BootstrapKey, Container>: AbstractEngine
where
    BootstrapKey: LweBootstrapKeyEntity,
{
    /// Retrieves the content of the container from an LWE bootstrap key, consuming it in the
    /// process.
    fn consume_retrieve_lwe_bootstrap_key(
        &mut self,
        bootstrap_key: BootstrapKey,
    ) -> Result<Container, LweBootstrapKeyConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from an LWE bootstrap key, consuming it in
    /// the process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyConsumingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn consume_retrieve_lwe_bootstrap_key_unchecked(
        &mut self,
        bootstrap_key: BootstrapKey,
    ) -> Container;
}
