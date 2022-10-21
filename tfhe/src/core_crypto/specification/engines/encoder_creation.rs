use super::engine_error;
use crate::core_crypto::prelude::EncoderEntity;
use crate::core_crypto::specification::engines::AbstractEngine;

engine_error! {
    EncoderCreationError for EncoderCreationEngine @
}

/// A trait for engines creating encoders from configurations.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an encoder from the `config`
/// configuration.
///
/// # Formal Definition
pub trait EncoderCreationEngine<Config, Encoder>: AbstractEngine
where
    Encoder: EncoderEntity,
{
    /// Creates an encoder from a config.
    fn create_encoder_from(
        &mut self,
        config: &Config,
    ) -> Result<Encoder, EncoderCreationError<Self::EngineError>>;

    /// Unsafely creates an encoder from a config.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`EncoderCreationError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn create_encoder_from_unchecked(&mut self, config: &Config) -> Encoder;
}
