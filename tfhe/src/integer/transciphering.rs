use crate::integer::{RadixCiphertext, ServerKey};
use crate::transciphering::Transcipherer;

pub trait IntegerTranscipherer {
    fn next_keystream_radix(&mut self, sks: &ServerKey, n_bits: usize) -> RadixCiphertext;

    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext;
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn next_keystream_radix(&mut self, sks: &ServerKey, n_bits: usize) -> RadixCiphertext {
        RadixCiphertext::from(self.next_keystream_bits(&sks.key, n_bits))
    }

    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext {
        RadixCiphertext::from(self.trans_cipher(&sks.key, input_stream))
    }
}
