use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyConversionError for LweKeyswitchKeyConversionEngine @
}

/// A trait for engines converting LWE keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a LWE keyswitch key containing the
/// conversion of the `input` LWE keyswitch key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweKeyswitchKeyConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweKeyswitchKeyEntity,
    Output: LweKeyswitchKeyEntity,
{
    /// Converts a LWE keyswitch key.
    fn convert_lwe_keyswitch_key(
        &mut self,
        input: &Input,
    ) -> Result<Output, LweKeyswitchKeyConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_lwe_keyswitch_key_unchecked(&mut self, input: &Input) -> Output;
}
