use crate::core_crypto::commons::crypto::encoding::{Encoder, PlaintextList};
use crate::core_crypto::prelude::{
    CleartextVectorEncodingEngine, CleartextVectorEncodingError, CleartextVectorF64, DefaultEngine,
    DefaultError, FloatEncoderVector, PlaintextVector32, PlaintextVector64,
};

/// # Description:
/// Implementation of [`CleartextVectorEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 32 bits integers.
impl CleartextVectorEncodingEngine<FloatEncoderVector, CleartextVectorF64, PlaintextVector32>
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
    ///     FloatEncoderMinMaxConfig {
    ///         min: 0.,
    ///         max: 10.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     100
    /// ])?;
    /// let cleartext_vector: CleartextVectorF64 =
    ///     engine.create_cleartext_vector_from(&vec![5.; 100])?;
    /// let plaintext_vector: PlaintextVector32 =
    ///     engine.encode_cleartext_vector(&encoder_vector, &cleartext_vector)?;
    /// assert_eq!(
    ///     cleartext_vector.cleartext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext_vector(
        &mut self,
        encoder_vector: &FloatEncoderVector,
        cleartext_vector: &CleartextVectorF64,
    ) -> Result<PlaintextVector32, CleartextVectorEncodingError<Self::EngineError>> {
        CleartextVectorEncodingError::perform_generic_checks(encoder_vector, cleartext_vector)?;
        let interval_check_failed = encoder_vector
            .0
            .iter()
            .zip(cleartext_vector.0.cleartext_iter())
            .any(|(encoder, cleartext)| encoder.is_message_out_of_range(cleartext.0));
        if interval_check_failed {
            return Err(CleartextVectorEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_vector_unchecked(encoder_vector, cleartext_vector) })
    }

    unsafe fn encode_cleartext_vector_unchecked(
        &mut self,
        encoder_vector: &FloatEncoderVector,
        cleartext_vector: &CleartextVectorF64,
    ) -> PlaintextVector32 {
        PlaintextVector32(PlaintextList::from_container(
            encoder_vector
                .0
                .iter()
                .zip(cleartext_vector.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}

/// # Description:
/// Implementation of [`CleartextVectorEncodingEngine`] for [`DefaultEngine`] that encodes 64 bits
/// floating point numbers to 64 bits integers.
impl CleartextVectorEncodingEngine<FloatEncoderVector, CleartextVectorF64, PlaintextVector64>
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
    ///     FloatEncoderMinMaxConfig {
    ///         min: 0.,
    ///         max: 10.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     100
    /// ])?;
    /// let cleartext_vector: CleartextVectorF64 =
    ///     engine.create_cleartext_vector_from(&vec![5.; 100])?;
    /// let plaintext_vector: PlaintextVector64 =
    ///     engine.encode_cleartext_vector(&encoder_vector, &cleartext_vector)?;
    /// assert_eq!(
    ///     cleartext_vector.cleartext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encode_cleartext_vector(
        &mut self,
        encoder_vector: &FloatEncoderVector,
        cleartext_vector: &CleartextVectorF64,
    ) -> Result<PlaintextVector64, CleartextVectorEncodingError<Self::EngineError>> {
        CleartextVectorEncodingError::perform_generic_checks(encoder_vector, cleartext_vector)?;
        let interval_check_failed = encoder_vector
            .0
            .iter()
            .zip(cleartext_vector.0.cleartext_iter())
            .any(|(encoder, cleartext)| encoder.is_message_out_of_range(cleartext.0));
        if interval_check_failed {
            return Err(CleartextVectorEncodingError::Engine(
                DefaultError::FloatEncoderMessageOutsideInterval,
            ));
        }
        Ok(unsafe { self.encode_cleartext_vector_unchecked(encoder_vector, cleartext_vector) })
    }

    unsafe fn encode_cleartext_vector_unchecked(
        &mut self,
        encoder_vector: &FloatEncoderVector,
        cleartext_vector: &CleartextVectorF64,
    ) -> PlaintextVector64 {
        PlaintextVector64(PlaintextList::from_container(
            encoder_vector
                .0
                .iter()
                .zip(cleartext_vector.0.cleartext_iter())
                .map(|(enc, clear)| enc.encode(*clear).0)
                .collect::<Vec<_>>(),
        ))
    }
}
