use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::transciphering::Transcipherer;

pub trait IntegerTranscipherer {
    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext;

    fn trans_cipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &[u8],
    ) -> SignedRadixCiphertext;
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn trans_cipher_radix(&mut self, sks: &ServerKey, input_stream: &[u8]) -> RadixCiphertext {
        RadixCiphertext::from(self.trans_cipher(&sks.key, input_stream))
    }

    fn trans_cipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &[u8],
    ) -> SignedRadixCiphertext {
        SignedRadixCiphertext::from(self.trans_cipher(&sks.key, input_stream))
    }
}
