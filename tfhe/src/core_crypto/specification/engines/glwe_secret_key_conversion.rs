use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyConversionError for GlweSecretKeyConversionEngine @
}

/// A trait for engines converting GLWE secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a GLWE secret key containing the
/// conversion of the `input` GLWE secret key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait GlweSecretKeyConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweSecretKeyEntity,
    Output: GlweSecretKeyEntity,
{
    /// Converts a GLWE secret key.
    fn convert_glwe_secret_key(
        &mut self,
        input: &Input,
    ) -> Result<Output, GlweSecretKeyConversionError<Self::EngineError>>;

    /// Unsafely converts a GLWE secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSecretKeyConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_glwe_secret_key_unchecked(&mut self, input: &Input) -> Output;
}
