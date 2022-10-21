use super::engine_error;
use crate::core_crypto::prelude::AbstractEngine;

use crate::core_crypto::specification::entities::{GlweSecretKeyEntity, LweSecretKeyEntity};

engine_error! {
    GlweToLweSecretKeyTransformationError for GlweToLweSecretKeyTransformationEngine @
}

/// A trait for engines transforming GLWE secret keys into LWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation moves the existing GLWE into a fresh LWE secret
/// key.
///
/// # Formal Definition
pub trait GlweToLweSecretKeyTransformationEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: GlweSecretKeyEntity,
    OutputKey: LweSecretKeyEntity,
{
    /// Does the transformation of the GLWE secret key into an LWE secret key
    fn transform_glwe_secret_key_to_lwe_secret_key(
        &mut self,
        glwe_secret_key: InputKey,
    ) -> Result<OutputKey, GlweToLweSecretKeyTransformationError<Self::EngineError>>;

    /// Unsafely transforms a GLWE secret key into an LWE secret key
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweToLweSecretKeyTransformationError`].
    /// For safety concerns _specific_ to an engine, refer to the implementer safety section.
    unsafe fn transform_glwe_secret_key_to_lwe_secret_key_unchecked(
        &mut self,
        glwe_secret_key: InputKey,
    ) -> OutputKey;
}
