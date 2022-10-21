use super::engine_error;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, LweDimension,
};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyCreationError for LweKeyswitchKeyCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    InvalidContainerSize => "The length of the container used to create the LWE Keyswitch key \
                              needs to be a multiple of \
                              `decomposition_level_count * output_lwe_size`."
}

impl<EngineError: std::error::Error> LweKeyswitchKeyCreationError<EngineError> {
    pub fn perform_generic_checks(
        container_length: usize,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }
        if container_length % (decomposition_level_count.0 * output_lwe_dimension.to_lwe_size().0)
            != 0
        {
            return Err(Self::InvalidContainerSize);
        }
        Ok(())
    }
}

/// A trait for engines creating LWE Keyswitch keys from existing containers.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation constructs an LWE Keyswitch key from the given
/// `container`.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LweKeyswitchKeyEntity`)
pub trait LweKeyswitchKeyCreationEngine<Container, KeyswitchKey>: AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity,
{
    /// Creates an LWE keyswitch key from an existing container.
    fn create_lwe_keyswitch_key_from(
        &mut self,
        container: Container,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<KeyswitchKey, LweKeyswitchKeyCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE keyswitch key from an existing container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyCreationError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn create_lwe_keyswitch_key_from_unchecked(
        &mut self,
        container: Container,
        output_lwe_dimension: LweDimension,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> KeyswitchKey;
}
