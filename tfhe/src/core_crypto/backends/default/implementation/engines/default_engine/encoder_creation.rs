use crate::core_crypto::prelude::{
    DefaultEngine, DefaultError, EncoderCreationEngine, EncoderCreationError, FloatEncoder,
    FloatEncoderCenterRadiusConfig, FloatEncoderMinMaxConfig,
};

/// # Description:
/// Implementation of [`EncoderCreationEngine`] for [`DefaultEngine`] that creates an encoder to
/// encode 64 bits floating point numbers.
impl EncoderCreationEngine<FloatEncoderMinMaxConfig, FloatEncoder> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder = engine.create_encoder_from(&FloatEncoderMinMaxConfig {
    ///     min: 0.,
    ///     max: 10.,
    ///     nb_bit_precision: 8,
    ///     nb_bit_padding: 1,
    /// })?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_from(
        &mut self,
        config: &FloatEncoderMinMaxConfig,
    ) -> Result<FloatEncoder, EncoderCreationError<Self::EngineError>> {
        if config.min >= config.max {
            return Err(EncoderCreationError::Engine(
                DefaultError::FloatEncoderMinMaxOrder,
            ));
        } else if config.nb_bit_precision == 0 {
            return Err(EncoderCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_from_unchecked(config) })
    }

    unsafe fn create_encoder_from_unchecked(
        &mut self,
        config: &FloatEncoderMinMaxConfig,
    ) -> FloatEncoder {
        FloatEncoder(config.to_commons())
    }
}

/// # Description:
/// Implementation of [`EncoderCreationEngine`] for [`DefaultEngine`] that creates an encoder to
/// encode 64 bits floating point numbers.
impl EncoderCreationEngine<FloatEncoderCenterRadiusConfig, FloatEncoder> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder = engine.create_encoder_from(&FloatEncoderCenterRadiusConfig {
    ///     center: 10.,
    ///     radius: 5.,
    ///     nb_bit_precision: 8,
    ///     nb_bit_padding: 1,
    /// })?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_from(
        &mut self,
        config: &FloatEncoderCenterRadiusConfig,
    ) -> Result<FloatEncoder, EncoderCreationError<Self::EngineError>> {
        if config.radius <= 0. {
            return Err(EncoderCreationError::Engine(
                DefaultError::FloatEncoderNullRadius,
            ));
        } else if config.nb_bit_precision == 0 {
            return Err(EncoderCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_from_unchecked(config) })
    }

    unsafe fn create_encoder_from_unchecked(
        &mut self,
        config: &FloatEncoderCenterRadiusConfig,
    ) -> FloatEncoder {
        FloatEncoder(config.to_commons())
    }
}
