use super::engine_error;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSecretKeyEntity,
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity, LweSecretKeyEntity, Variance,
};
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError for
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

impl<EngineError: std::error::Error>
    LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError<EngineError>
{
    /// Validates the inputs
    pub fn perform_generic_checks(
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        ciphertext_modulus_log: usize,
    ) -> Result<(), Self> {
        if decomposition_base_log.0 == 0 {
            return Err(Self::NullDecompositionBaseLog);
        }

        if decomposition_level_count.0 == 0 {
            return Err(Self::NullDecompositionLevelCount);
        }

        if decomposition_level_count.0 * decomposition_base_log.0 > ciphertext_modulus_log {
            return Err(Self::DecompositionTooLarge);
        }

        Ok(())
    }
}

/// A trait for engines generating new LWE functional packing keyswitch keys used in a circuit
/// bootstrapping.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new set of LWE private functional
/// packing keyswitch key required to perform a circuit bootstrapping.
///
/// # Formal Definition
pub trait LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationEngine<
    InputLweSecretKey,
    OutputGlweSecretKey,
    CBSFPKSK,
>: AbstractEngine where
    InputLweSecretKey: LweSecretKeyEntity,
    OutputGlweSecretKey: GlweSecretKeyEntity,
    CBSFPKSK: LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysEntity,
{
    /// Generate a new LWE CBSFPKSK.
    fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys(
        &mut self,
        input_lwe_key: &InputLweSecretKey,
        output_glwe_key: &OutputGlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<
        CBSFPKSK,
        LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError<Self::EngineError>,
    >;

    /// Unsafely generate a new LWE CBSFPKSK.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCircuitBootstrapPrivateFunctionalPackingKeyswitchKeysGenerationError`]. For safety
    /// concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn generate_new_lwe_circuit_bootstrap_private_functional_packing_keyswitch_keys_unchecked(
        &mut self,
        input_lwe_key: &InputLweSecretKey,
        output_glwe_key: &OutputGlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> CBSFPKSK;
}
