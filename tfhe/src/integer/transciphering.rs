use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::transciphering::Transcipherer;

pub trait IntegerTranscipherer {
    fn next_keystream_radix(&mut self, sks: &ServerKey, n_bits: usize) -> RadixCiphertext;

    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext;

    fn next_keystream_signed_radix(
        &mut self,
        sks: &ServerKey,
        n_bits: usize,
    ) -> SignedRadixCiphertext;

    fn trans_cipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &[u8],
    ) -> SignedRadixCiphertext;
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn next_keystream_radix(&mut self, sks: &ServerKey, n_bits: usize) -> RadixCiphertext {
        RadixCiphertext::from(self.next_keystream_bits(&sks.key, n_bits))
    }

    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext {
        RadixCiphertext::from(self.trans_cipher(&sks.key, input_stream))
    }

    fn next_keystream_signed_radix(
        &mut self,
        sks: &ServerKey,
        n_bits: usize,
    ) -> SignedRadixCiphertext {
        SignedRadixCiphertext::from(self.next_keystream_bits(&sks.key, n_bits))
    }

    fn trans_cipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &[u8],
    ) -> SignedRadixCiphertext {
        SignedRadixCiphertext::from(self.trans_cipher(&sks.key, input_stream))
    }
}
