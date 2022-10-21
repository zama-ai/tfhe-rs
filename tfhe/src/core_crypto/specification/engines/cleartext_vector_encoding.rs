use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    CleartextVectorEntity, EncoderVectorEntity, PlaintextVectorEntity,
};

engine_error! {
    CleartextVectorEncodingError for CleartextVectorEncodingEngine @
    EncoderCountMismatch => "The encoder count and cleartext count must be the same."
}

impl<EngineError: std::error::Error> CleartextVectorEncodingError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<EncoderVector, CleartextVector>(
        encoder_vector: &EncoderVector,
        cleartext_vector: &CleartextVector,
    ) -> Result<(), Self>
    where
        EncoderVector: EncoderVectorEntity,
        CleartextVector: CleartextVectorEntity,
    {
        if encoder_vector.encoder_count().0 != cleartext_vector.cleartext_count().0 {
            return Err(Self::EncoderCountMismatch);
        }
        Ok(())
    }
}

/// A trait for engines encoding cleartext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// element-wise encodings of the `cleartext_vector` cleartext vector under the `encoder_vector`
/// encoder vector.
///
/// # Formal Definition
pub trait CleartextVectorEncodingEngine<EncoderVector, CleartextVector, PlaintextVector>:
    AbstractEngine
where
    EncoderVector: EncoderVectorEntity,
    CleartextVector: CleartextVectorEntity,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Encodes a cleartext vector into a plaintext vector.
    fn encode_cleartext_vector(
        &mut self,
        encoder_vector: &EncoderVector,
        cleartext_vector: &CleartextVector,
    ) -> Result<PlaintextVector, CleartextVectorEncodingError<Self::EngineError>>;

    /// Unsafely encodes a cleartext vector into a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorEncodingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encode_cleartext_vector_unchecked(
        &mut self,
        encoder_vector: &EncoderVector,
        cleartext_vector: &CleartextVector,
    ) -> PlaintextVector;
}
