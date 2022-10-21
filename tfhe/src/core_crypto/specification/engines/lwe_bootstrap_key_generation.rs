use super::engine_error;
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweSecretKeyEntity,
};

engine_error! {
    LweBootstrapKeyGenerationError for LweBootstrapKeyGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

impl<EngineError: std::error::Error> LweBootstrapKeyGenerationError<EngineError> {
    pub fn perform_generic_checks(
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
        Ok(())
    }
}

/// A trait for engines generating new LWE bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new LWE bootstrap key from the
/// `input_key` LWE secret key, and the `output_key` GLWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LweBootstrapKeyEntity`)
pub trait LweBootstrapKeyGenerationEngine<LweSecretKey, GlweSecretKey, BootstrapKey>:
    AbstractEngine
where
    BootstrapKey: LweBootstrapKeyEntity,
    LweSecretKey: LweSecretKeyEntity,
    GlweSecretKey: GlweSecretKeyEntity,
{
    /// Generates a new LWE bootstrap key.
    fn generate_new_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey,
        output_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<BootstrapKey, LweBootstrapKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates a new LWE bootstrap key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyGenerationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn generate_new_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey,
        output_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> BootstrapKey;
}
