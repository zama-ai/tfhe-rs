use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    CleartextEntity, EncoderEntity, PlaintextEntity,
};

engine_error! {
    CleartextEncodingError for CleartextEncodingEngine @
}

/// A trait for engines encoding cleartexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext containing the encoding
/// of the `cleartext` cleartext, under the `encoder` encoder.
///
/// # Formal Definition
pub trait CleartextEncodingEngine<Encoder, Cleartext, Plaintext>: AbstractEngine
where
    Encoder: EncoderEntity,
    Cleartext: CleartextEntity,
    Plaintext: PlaintextEntity,
{
    /// Encodes a cleartext into a plaintext.
    fn encode_cleartext(
        &mut self,
        encoder: &Encoder,
        cleartext: &Cleartext,
    ) -> Result<Plaintext, CleartextEncodingError<Self::EngineError>>;

    /// Unsafely encodes a cleartext into a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextEncodingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encode_cleartext_unchecked(
        &mut self,
        encoder: &Encoder,
        cleartext: &Cleartext,
    ) -> Plaintext;
}
