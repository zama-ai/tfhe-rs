use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{
    LweKeyswitchKeyEntity, LweSeededKeyswitchKeyEntity,
};

engine_error! {
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError for
    LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine @
}

/// A trait for engines transforming LWE seeded ciphertexts into LWE ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing seeded LWE keyswitch key
/// into an LWE keyswitch key.
///
/// # Formal Definition
///
/// ## LWE seeded keyswitch key to LWE keyswitch key transformation
///
/// TODO

pub trait LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationEngine<InputKey, OutputKey>:
    AbstractEngine
where
    InputKey: LweSeededKeyswitchKeyEntity,
    OutputKey: LweKeyswitchKeyEntity,
{
    /// Does the transformation of the seeded LWE keyswitch key into an LWE keyswitch key
    fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key(
        &mut self,
        lwe_seeded_keyswitch_key: InputKey,
    ) -> Result<
        OutputKey,
        LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError<Self::EngineError>,
    >;

    /// Unsafely transforms a seeded LWE keyswitch key into an LWE keyswitch key
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSeededKeyswitchKeyToLweKeyswitchKeyTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_lwe_seeded_keyswitch_key_to_lwe_keyswitch_key_unchecked(
        &mut self,
        lwe_seeded_keyswitch_key: InputKey,
    ) -> OutputKey;
}
