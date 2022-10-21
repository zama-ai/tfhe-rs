use super::engine_error;
use crate::core_crypto::specification::engines::AbstractEngine;
use crate::core_crypto::specification::entities::{
    CleartextEntity, EncoderEntity, PlaintextEntity,
};

engine_error! {
    PlaintextDecodingError for PlaintextDecodingEngine @
}

/// A trait for engines decoding plaintexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext containing the decoding
/// of the `input` plaintext under the `encoder` encoder.
///
/// # Formal Definition
pub trait PlaintextDecodingEngine<Encoder, Plaintext, Cleartext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
    Cleartext: CleartextEntity,
    Encoder: EncoderEntity,
{
    /// Decodes a plaintext.
    fn decode_plaintext(
        &mut self,
        encoder: &Encoder,
        input: &Plaintext,
    ) -> Result<Cleartext, PlaintextDecodingError<Self::EngineError>>;

    /// Unsafely decodes a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextDecodingError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn decode_plaintext_unchecked(
        &mut self,
        input: &Plaintext,
        encoder: &Encoder,
    ) -> Cleartext;
}
