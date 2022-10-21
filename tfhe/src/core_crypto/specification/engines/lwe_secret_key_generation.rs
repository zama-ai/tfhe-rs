use crate::core_crypto::prelude::LweDimension;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

engine_error! {
    LweSecretKeyGenerationError for LweSecretKeyGenerationEngine @
    NullLweDimension => "The LWE dimension must be greater than zero."
}

impl<EngineError: std::error::Error> LweSecretKeyGenerationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(lwe_dimension: LweDimension) -> Result<(), Self> {
        if lwe_dimension.0 == 0 {
            return Err(Self::NullLweDimension);
        }
        Ok(())
    }
}

/// A trait for engines generating new LWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new LWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::LweSecretKeyEntity`)
pub trait LweSecretKeyGenerationEngine<SecretKey>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
{
    /// Generates a new LWE secret key.
    fn generate_new_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<SecretKey, LweSecretKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates a new LWE secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSecretKeyGenerationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn generate_new_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> SecretKey;
}
