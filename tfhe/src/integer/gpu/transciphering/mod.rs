pub mod ciphers;

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::CudaServerKey;
use crate::integer::transciphering::{
    check_kind, IntegerStreamCiphertext, IntegerStreamCiphertextKind, IntegerTranscipherError,
};
use crate::transciphering::{
    check_transcipher_input, StreamCipherKind, StreamCiphertext, TranscipherError,
    TranscipheringOutputLayout,
};

use super::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};

/// FHE-encrypted keystream returned by
/// [`CudaIntegerTranscipherer::next_keystream_bits`], GPU counterpart of
/// [`crate::transciphering::FheKeyStream`].
///
/// Bits are packed as the blocks of an unsigned radix: one block per
/// keystream bit, low bit first.
pub struct CudaFheKeyStream(CudaUnsignedRadixCiphertext);

impl CudaFheKeyStream {
    pub fn from_raw_parts(bits: CudaUnsignedRadixCiphertext) -> Self {
        Self(bits)
    }

    pub fn into_raw_parts(self) -> CudaUnsignedRadixCiphertext {
        self.0
    }

    pub fn as_radix(&self) -> &CudaUnsignedRadixCiphertext {
        &self.0
    }
}

pub trait CudaIntegerTranscipherer {
    /// Cipher family this session belongs to. Must match the
    /// [`StreamCiphertext::kind`] of any input passed to [`Self::transcipher`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter.
    fn next_keystream_bits(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> CudaFheKeyStream;

    /// Transcipher `input` against `input.n_bits()` bits of keystream from
    /// this session, advancing the internal counter.
    ///
    /// This will produce a list of ciphertexts, according to the provided
    /// `output_layout`.
    ///
    /// Returns [`TranscipherError::KeystreamProductionError`] if the transcipherer cannot produce
    /// enough bits to cover the input.
    fn transcipher(
        &mut self,
        sks: &CudaServerKey,
        input: &StreamCiphertext,
        output_layout: &TranscipheringOutputLayout,
        streams: &CudaStreams,
    ) -> Result<CudaRadixCiphertext, TranscipherError> {
        check_transcipher_input(
            self.kind(),
            self.current_counter(),
            input,
            output_layout,
            sks.message_modulus,
        )?;

        let keystream = self.next_keystream_bits(sks, input.n_bits(), streams);
        Ok(apply_keystream(
            sks,
            &keystream,
            input,
            output_layout,
            streams,
        ))
    }

    fn transcipher_radix(
        &mut self,
        sks: &CudaServerKey,
        input: &IntegerStreamCiphertext,
        streams: &CudaStreams,
    ) -> Result<CudaUnsignedRadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Unsigned)?;
        let layout = input.output_layout(sks.message_modulus)?;
        let blocks = self.transcipher(sks, input.inner(), &layout, streams)?;
        Ok(<CudaUnsignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(blocks))
    }

    fn transcipher_signed_radix(
        &mut self,
        sks: &CudaServerKey,
        input: &IntegerStreamCiphertext,
        streams: &CudaStreams,
    ) -> Result<CudaSignedRadixCiphertext, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Signed)?;
        let layout = input.output_layout(sks.message_modulus)?;
        let blocks = self.transcipher(sks, input.inner(), &layout, streams)?;
        Ok(<CudaSignedRadixCiphertext as CudaIntegerRadixCiphertext>::from(blocks))
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &CudaServerKey, n_bits: usize, streams: &CudaStreams);

    fn current_counter(&self) -> u64;
}

/// XOR an FHE-encrypted keystream with a clear symmetric ciphertext.
///
/// GPU counterpart of [`crate::transciphering::apply_keystream`]
pub fn apply_keystream(
    _sks: &CudaServerKey,
    _keystream: &CudaFheKeyStream,
    _input_stream: &StreamCiphertext,
    _output_layout: &TranscipheringOutputLayout,
    _streams: &CudaStreams,
) -> CudaRadixCiphertext {
    unimplemented!("apply_keystream is not yet implemented for GPU")
}
