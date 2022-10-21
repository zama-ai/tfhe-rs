use crate::core_crypto::commons::crypto::encoding::{CleartextList, Encoder};
use crate::core_crypto::prelude::{
    CleartextVectorF64, DefaultEngine, FloatEncoderVector, PlaintextVector32, PlaintextVector64,
    PlaintextVectorDecodingEngine, PlaintextVectorDecodingError,
};

/// # Description:
/// Implementation of [`PlaintextVectorDecodingEngine`] for [`DefaultEngine`] that decodes 32 bits
/// integers to 64 bits floating point numbers.
impl PlaintextVectorDecodingEngine<FloatEncoderVector, PlaintextVector32, CleartextVectorF64>
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
    /// let recovered_cleartext_vector: CleartextVectorF64 =
    ///     engine.decode_plaintext_vector(&encoder_vector, &plaintext_vector)?;
    /// assert_eq!(
    ///     recovered_cleartext_vector.cleartext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext_vector(
        &mut self,
        encoder: &FloatEncoderVector,
        input: &PlaintextVector32,
    ) -> Result<CleartextVectorF64, PlaintextVectorDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_vector_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_vector_unchecked(
        &mut self,
        encoder: &FloatEncoderVector,
        input: &PlaintextVector32,
    ) -> CleartextVectorF64 {
        CleartextVectorF64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}

/// # Description:
/// Implementation of [`PlaintextVectorDecodingEngine`] for [`DefaultEngine`] that decodes 64 bits
/// integers to 64 bits floating point numbers.
impl PlaintextVectorDecodingEngine<FloatEncoderVector, PlaintextVector64, CleartextVectorF64>
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
    /// let recovered_cleartext_vector: CleartextVectorF64 =
    ///     engine.decode_plaintext_vector(&encoder_vector, &plaintext_vector)?;
    /// assert_eq!(
    ///     recovered_cleartext_vector.cleartext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn decode_plaintext_vector(
        &mut self,
        encoder: &FloatEncoderVector,
        input: &PlaintextVector64,
    ) -> Result<CleartextVectorF64, PlaintextVectorDecodingError<Self::EngineError>> {
        Ok(unsafe { self.decode_plaintext_vector_unchecked(encoder, input) })
    }

    unsafe fn decode_plaintext_vector_unchecked(
        &mut self,
        encoder: &FloatEncoderVector,
        input: &PlaintextVector64,
    ) -> CleartextVectorF64 {
        CleartextVectorF64(CleartextList::from_container(
            encoder
                .0
                .iter()
                .zip(input.0.plaintext_iter())
                .map(|(enc, p)| enc.decode(*p).0)
                .collect::<Vec<_>>(),
        ))
    }
}
