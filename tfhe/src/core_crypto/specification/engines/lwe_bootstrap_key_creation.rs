use super::engine_error;
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyCreationError for LweBootstrapKeyCreationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext.",
    InvalidContainerSize => "The length of the container used to create the LWE bootstrap key \
                              needs to be a multiple of \
                              `decomposition_level_count * glwe_size * glwe_size * poly_size`."
}

impl<EngineError: std::error::Error> LweBootstrapKeyCreationError<EngineError> {
    pub fn perform_generic_checks(
        container_length: usize,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
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
        if container_length
            % (decomposition_level_count.0 * glwe_size.0 * glwe_size.0 * poly_size.0)
            != 0
        {
            return Err(Self::InvalidContainerSize);
        }
        Ok(())
    }
}

/// A trait for engines creating LWE bootstrap keys from existing containers.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation constructs an LWE bootstrap key from the given
/// `container`.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LweBootstrapKeyEntity`)
pub trait LweBootstrapKeyCreationEngine<Container, BootstrapKey>: AbstractEngine
where
    BootstrapKey: LweBootstrapKeyEntity,
{
    /// Creates an LWE bootstrap key from an existing container.
    fn create_lwe_bootstrap_key_from(
        &mut self,
        container: Container,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Result<BootstrapKey, LweBootstrapKeyCreationError<Self::EngineError>>;

    /// Unsafely creates an LWE bootstrap key from an existing container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyCreationError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn create_lwe_bootstrap_key_from_unchecked(
        &mut self,
        container: Container,
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> BootstrapKey;
}
