use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::CudaServerKey;

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
    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter.
    fn next_keystream_bits(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> CudaFheKeyStream;

    /// Trans-cipher `input_stream` against `8 * input_stream.len()` bits of
    /// keystream from this session, advancing the internal counter.
    fn trans_cipher_radix(
        &mut self,
        sks: &CudaServerKey,
        input_stream: &[u8],
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let keystream = self.next_keystream_bits(sks, 8 * input_stream.len(), streams);
        apply_keystream(sks, &keystream, input_stream, streams)
    }

    /// Signed-radix counterpart of [`Self::trans_cipher_radix`]. Same flow,
    /// reinterpreted as a signed radix.
    fn trans_cipher_signed_radix(
        &mut self,
        sks: &CudaServerKey,
        input_stream: &[u8],
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext;

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &CudaServerKey, n_bits: usize, streams: &CudaStreams);

    fn current_counter(&self) -> u64;
}

/// XOR an FHE-encrypted keystream with a clear symmetric ciphertext.
///
/// GPU counterpart of [`crate::transciphering::apply_keystream`]:
/// `input_stream.len()` clear bytes are consumed (low-bit first within each
/// byte), so the keystream must contain exactly `8 * input_stream.len()` bits.
pub fn apply_keystream(
    _sks: &CudaServerKey,
    _keystream: &CudaFheKeyStream,
    _input_stream: &[u8],
    _streams: &CudaStreams,
) -> CudaUnsignedRadixCiphertext {
    unimplemented!("apply_keystream is not yet implemented for GPU")
}
