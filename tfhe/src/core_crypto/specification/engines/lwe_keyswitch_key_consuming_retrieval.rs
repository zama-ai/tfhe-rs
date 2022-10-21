use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyConsumingRetrievalError for LweKeyswitchKeyConsumingRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from an LWE keyswitch key consuming
/// it in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// input LWE keyswitch key consuming it in the process.
pub trait LweKeyswitchKeyConsumingRetrievalEngine<KeyswitchKey, Container>: AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity,
{
    /// Retrieves the content of the container from an LWE keyswitch key, consuming it in the
    /// process.
    fn consume_retrieve_lwe_keyswitch_key(
        &mut self,
        keyswitch_key: KeyswitchKey,
    ) -> Result<Container, LweKeyswitchKeyConsumingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from an LWE keyswitch key, consuming it in
    /// the process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyConsumingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn consume_retrieve_lwe_keyswitch_key_unchecked(
        &mut self,
        keyswitch_key: KeyswitchKey,
    ) -> Container;
}
