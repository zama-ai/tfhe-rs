use crate::core_crypto::commons::crypto::encoding::Encoder;
use crate::core_crypto::prelude::{
    CleartextEncodingEngine, CleartextEncodingError, CleartextF64, DefaultEngine, DefaultError,
    FloatEncoder, Plaintext32, Plaintext64,
};

/// # Description:
/// Implementation of [`CleartextEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 32 bits integers.
impl CleartextEncodingEngine<FloatEncoder, CleartextF64, Plaintext32> for DefaultEngine {
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
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&5.)?;
    /// let plaintext: Plaintext32 = engine.encode_cleartext(&encoder, &cleartext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> Result<Plaintext32, CleartextEncodingError<Self::EngineError>> {
        if encoder.0.is_message_out_of_range(cleartext.0 .0) {
            return Err(CleartextEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_unchecked(encoder, cleartext) })
    }

    unsafe fn encode_cleartext_unchecked(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> Plaintext32 {
        Plaintext32(encoder.0.encode(cleartext.0))
    }
}

/// # Description:
/// Implementation of [`CleartextEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 32 bits integers.
impl CleartextEncodingEngine<FloatEncoder, CleartextF64, Plaintext64> for DefaultEngine {
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
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&5.)?;
    /// let plaintext: Plaintext64 = engine.encode_cleartext(&encoder, &cleartext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> Result<Plaintext64, CleartextEncodingError<Self::EngineError>> {
        if encoder.0.is_message_out_of_range(cleartext.0 .0) {
            return Err(CleartextEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_unchecked(encoder, cleartext) })
    }

    unsafe fn encode_cleartext_unchecked(
        &mut self,
        encoder: &FloatEncoder,
        cleartext: &CleartextF64,
    ) -> Plaintext64 {
        Plaintext64(encoder.0.encode(cleartext.0))
    }
}
