use super::engine_error;
use crate::core_crypto::prelude::EncoderVectorEntity;
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    EncoderVectorCreationError for EncoderVectorCreationEngine @
}

/// A trait for engines creating encoder vectors from configurations.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an encoder vector from the `config`
/// configuration.
///
/// # Formal Definition
pub trait EncoderVectorCreationEngine<Config, EncoderVector>: AbstractEngine
where
    EncoderVector: EncoderVectorEntity,
{
    /// Creates an encoder vector from a config.
    fn create_encoder_vector_from(
        &mut self,
        config: &[Config],
    ) -> Result<EncoderVector, EncoderVectorCreationError<Self::EngineError>>;

    /// Unsafely creates an encoder vector from a config.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`EncoderVectorCreationError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn create_encoder_vector_from_unchecked(&mut self, config: &[Config]) -> EncoderVector;
}
