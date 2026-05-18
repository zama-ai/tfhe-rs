use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::CudaServerKey;
use crate::transciphering::TranscipheringCipherKind;

pub trait CudaIntegerTranscipherer {
    fn kind(&self) -> TranscipheringCipherKind;

    fn next_keystream_radix(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext;

    fn trans_cipher_radix(
        &mut self,
        sks: &CudaServerKey,
        input_stream: &[u8],
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext;

    fn next_keystream_signed_radix(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext;

    fn trans_cipher_signed_radix(
        &mut self,
        sks: &CudaServerKey,
        input_stream: &[u8],
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext;

    fn skip(&mut self, sks: &CudaServerKey, n_bits: usize, streams: &CudaStreams);

    fn current_counter(&self) -> u64;
}
