use crate::core_crypto::commons::crypto::encoding::Encoder;
use crate::core_crypto::prelude::{
    CleartextF64, DefaultEngine, FloatEncoder, Plaintext32, Plaintext64, PlaintextDecodingEngine,
    PlaintextDecodingError,
};

/// # Description:
/// Implementation of [`PlaintextDecodingEngine`] for [`DefaultEngine`] that decodes 32 bits
/// integers to 64 bits floating point numbers.
impl PlaintextDecodingEngine<FloatEncoder, Plaintext32, CleartextF64> for DefaultEngine {
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
    /// let recovered_cleartext: CleartextF64 = engine.decode_plaintext(&encoder, &plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext(
        &mut self,
        encoder: &FloatEncoder,
        input: &Plaintext32,
    ) -> Result<CleartextF64, PlaintextDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_unchecked(input, encoder) })
    }

    unsafe fn decode_plaintext_unchecked(
        &mut self,
        input: &Plaintext32,
        encoder: &FloatEncoder,
    ) -> CleartextF64 {
        CleartextF64(encoder.0.decode(input.0))
    }
}

/// # Description:
/// Implementation of [`PlaintextDecodingEngine`] for [`DefaultEngine`] that decodes 64 bits
/// integers to 64 bits floating point numbers.
impl PlaintextDecodingEngine<FloatEncoder, Plaintext64, CleartextF64> for DefaultEngine {
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
    /// let recovered_cleartext: CleartextF64 = engine.decode_plaintext(&encoder, &plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext(
        &mut self,
        encoder: &FloatEncoder,
        input: &Plaintext64,
    ) -> Result<CleartextF64, PlaintextDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_unchecked(input, encoder) })
    }

    unsafe fn decode_plaintext_unchecked(
        &mut self,
        input: &Plaintext64,
        encoder: &FloatEncoder,
    ) -> CleartextF64 {
        CleartextF64(encoder.0.decode(input.0))
    }
}
