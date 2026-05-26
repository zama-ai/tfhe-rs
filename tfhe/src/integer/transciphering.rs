use crate::integer::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::transciphering::{StreamCiphertext, TranscipherError, Transcipherer};

pub trait IntegerTranscipherer {
    fn transcipher_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &StreamCiphertext,
    ) -> Result<RadixCiphertext, TranscipherError>;

    fn transcipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &StreamCiphertext,
    ) -> Result<SignedRadixCiphertext, TranscipherError>;
}

impl<T: Transcipherer> IntegerTranscipherer for T {
    fn transcipher_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &StreamCiphertext,
    ) -> Result<RadixCiphertext, TranscipherError> {
        self.transcipher(&sks.key, input_stream)
            .map(RadixCiphertext::from)
    }

    fn transcipher_signed_radix(
        &mut self,
        sks: &ServerKey,
        input_stream: &StreamCiphertext,
    ) -> Result<SignedRadixCiphertext, TranscipherError> {
        self.transcipher(&sks.key, input_stream)
            .map(SignedRadixCiphertext::from)
    }
}
