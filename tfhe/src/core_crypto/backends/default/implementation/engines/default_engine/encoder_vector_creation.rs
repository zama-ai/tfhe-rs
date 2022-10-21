use crate::core_crypto::prelude::{
    DefaultEngine, DefaultError, EncoderVectorCreationEngine, EncoderVectorCreationError,
    FloatEncoderCenterRadiusConfig, FloatEncoderMinMaxConfig, FloatEncoderVector,
};

/// # Description:
/// Implementation of [`EncoderVectorCreationEngine`] for [`DefaultEngine`] that creates an encoder
/// vector to encode vectors of 64 bits floating point numbers.
impl EncoderVectorCreationEngine<FloatEncoderMinMaxConfig, FloatEncoderVector> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder_vector = engine.create_encoder_vector_from(
    ///     vec![
    ///         FloatEncoderMinMaxConfig {
    ///             min: 0.,
    ///             max: 10.,
    ///             nb_bit_precision: 8,
    ///             nb_bit_padding: 1,
    ///         };
    ///         1
    ///     ]
    ///     .as_slice(),
    /// )?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_vector_from(
        &mut self,
        config: &[FloatEncoderMinMaxConfig],
    ) -> Result<FloatEncoderVector, EncoderVectorCreationError<Self::EngineError>> {
        if config.iter().any(|c| c.min >= c.max) {
            return Err(EncoderVectorCreationError::Engine(
                DefaultError::FloatEncoderMinMaxOrder,
            ));
        } else if config.iter().any(|c| c.nb_bit_precision == 0) {
            return Err(EncoderVectorCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_vector_from_unchecked(config) })
    }

    unsafe fn create_encoder_vector_from_unchecked(
        &mut self,
        config: &[FloatEncoderMinMaxConfig],
    ) -> FloatEncoderVector {
        FloatEncoderVector(
            config
                .iter()
                .map(FloatEncoderMinMaxConfig::to_commons)
                .collect(),
        )
    }
}

/// # Description:
/// Implementation of [`EncoderVectorCreationEngine`] for [`DefaultEngine`] that creates an encoder
/// vector to encode vectors of 64 bits floating point numbers.
impl EncoderVectorCreationEngine<FloatEncoderCenterRadiusConfig, FloatEncoderVector>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder_vector = engine.create_encoder_vector_from(&vec![
    ///     FloatEncoderCenterRadiusConfig {
    ///         center: 10.,
    ///         radius: 5.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     1
    /// ])?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_encoder_vector_from(
        &mut self,
        config: &[FloatEncoderCenterRadiusConfig],
    ) -> Result<FloatEncoderVector, EncoderVectorCreationError<Self::EngineError>> {
        if config.iter().any(|c| c.radius <= 0.) {
            return Err(EncoderVectorCreationError::Engine(
                DefaultError::FloatEncoderNullRadius,
            ));
        } else if config.iter().any(|c| c.nb_bit_precision == 0) {
            return Err(EncoderVectorCreationError::Engine(
                DefaultError::FloatEncoderNullPrecision,
            ));
        }
        Ok(unsafe { self.create_encoder_vector_from_unchecked(config) })
    }

    unsafe fn create_encoder_vector_from_unchecked(
        &mut self,
        config: &[FloatEncoderCenterRadiusConfig],
    ) -> FloatEncoderVector {
        FloatEncoderVector(
            config
                .iter()
                .map(FloatEncoderCenterRadiusConfig::to_commons)
                .collect(),
        )
    }
}
