use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    CleartextVectorEntity, EncoderVectorEntity, PlaintextVectorEntity,
};

engine_error! {
    PlaintextVectorDecodingError for PlaintextVectorDecodingEngine @
    EncoderCountMismatch => "The encoder count and plaintext count must be the same."
}

impl<EngineError: std::error::Error> PlaintextVectorDecodingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<EncoderVector, PlaintextVector>(
        encoder: &EncoderVector,
        input: &PlaintextVector,
    ) -> Result<(), Self>
    where
        EncoderVector: EncoderVectorEntity,
        PlaintextVector: PlaintextVectorEntity,
    {
        if input.plaintext_count().0 != encoder.encoder_count().0 {
            return Err(Self::EncoderCountMismatch);
        }
        Ok(())
    }
}
/// A trait for engines decoding plaintext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext vector containing the
/// element-wise decodings of the `input` plaintext vector, under the `encoder` encoder vector.
///
/// # Formal Definition
pub trait PlaintextVectorDecodingEngine<EncoderVector, PlaintextVector, CleartextVector>:
    AbstractEngine
where
    EncoderVector: EncoderVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
    CleartextVector: CleartextVectorEntity,
{
    /// Decodes a plaintext vector.
    fn decode_plaintext_vector(
        &mut self,
        encoder: &EncoderVector,
        input: &PlaintextVector,
    ) -> Result<CleartextVector, PlaintextVectorDecodingError<Self::EngineError>>;

    /// Unsafely decodes a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorDecodingError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn decode_plaintext_vector_unchecked(
        &mut self,
        encoder: &EncoderVector,
        input: &PlaintextVector,
    ) -> CleartextVector;
}
