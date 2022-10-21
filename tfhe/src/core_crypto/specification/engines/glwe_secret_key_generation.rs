use super::engine_error;
use crate::core_crypto::prelude::{GlweDimension, PolynomialSize};
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyGenerationError for GlweSecretKeyGenerationEngine @
    NullGlweDimension => "The secret key GLWE dimension must be greater than zero.",
    NullPolynomialSize => "The secret key polynomial size must be greater than zero.",
    SizeOnePolynomial => "The secret key polynomial size must be greater than one. Otherwise you \
                          should prefer the LWE scheme."
}

impl<EngineError: std::error::Error> GlweSecretKeyGenerationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<(), Self> {
        if glwe_dimension.0 == 0 {
            return Err(Self::NullGlweDimension);
        }

        if polynomial_size.0 == 0 {
            return Err(Self::NullPolynomialSize);
        }

        if polynomial_size.0 == 1 {
            return Err(Self::SizeOnePolynomial);
        }

        Ok(())
    }
}

/// A trait for engines generating new GLWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a new GLWE secret key.
///
/// # Formal Definition
///
/// cf [`here`](`crate::core_crypto::specification::entities::GlweSecretKeyEntity`)
pub trait GlweSecretKeyGenerationEngine<SecretKey>: AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
{
    /// Generates a new GLWE secret key.
    fn generate_new_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<SecretKey, GlweSecretKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates a new GLWE secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSecretKeyGenerationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn generate_new_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> SecretKey;
}
