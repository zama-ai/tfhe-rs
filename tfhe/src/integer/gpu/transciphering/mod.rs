pub mod ciphers;
#[cfg(test)]
mod test;

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;
use crate::integer::gpu::{
    cuda_backend_apply_keystream, cuda_backend_get_apply_keystream_size_on_gpu, CudaServerKey,
};
use crate::integer::transciphering::{
    check_kind, IntegerStreamCiphertext, IntegerStreamCiphertextKind, IntegerTranscipherError,
};
use crate::shortint::ciphertext::NoiseLevel;
use crate::transciphering::{
    check_transcipher_input, FheKeyStreamError, KeyStreamLayout, StreamApplicationPlan,
    StreamCipherKind, StreamCiphertext, TranscipherError, TranscipheringOutputLayout,
};

use super::ciphertext::{CudaIntegerRadixCiphertext, CudaRadixCiphertext};

/// FHE-encrypted keystream returned by
/// [`CudaIntegerTranscipherer::next_keystream_bits`], GPU counterpart of
/// [`crate::transciphering::FheKeyStream`].
///
/// The radix is only a container. Its blocks are the keystream ciphertexts, low bits first, with
/// [KeyStreamLayout::bits_per_ct] bits each.
pub struct CudaFheKeyStream {
    stream: CudaUnsignedRadixCiphertext,
    layout: KeyStreamLayout,
}

impl CudaFheKeyStream {
    /// Every block must have the degree of the layout (2^bits_per_ct - 1) and a nominal noise
    /// level, as [crate::transciphering::FheKeyStream::try_new] requires on CPU
    pub fn try_new(
        stream: CudaUnsignedRadixCiphertext,
        layout: KeyStreamLayout,
    ) -> Result<Self, FheKeyStreamError> {
        let bits_per_ct = u32::from(layout.bits_per_ct().get());

        for (index, block) in stream.as_ref().info.blocks.iter().enumerate() {
            // The first test keeps expected_degree from overflowing its shift
            if bits_per_ct >= u64::BITS
                || block.degree != layout.expected_degree()
                || block.noise_level != NoiseLevel::NOMINAL
            {
                return Err(FheKeyStreamError::InvalidCiphertext {
                    index,
                    degree: block.degree,
                    noise_level: block.noise_level,
                });
            }
        }

        Ok(Self { stream, layout })
    }

    pub fn into_raw_parts(self) -> (CudaUnsignedRadixCiphertext, KeyStreamLayout) {
        (self.stream, self.layout)
    }

    pub fn layout(&self) -> &KeyStreamLayout {
        &self.layout
    }

    pub fn len(&self) -> usize {
        self.stream.as_ref().d_blocks.lwe_ciphertext_count().0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait CudaIntegerTranscipherer {
    /// Cipher family this session belongs to. Must match the
    /// [`StreamCiphertext::kind`] of any input passed to [`Self::transcipher`].
    fn kind(&self) -> StreamCipherKind;

    /// Produce the next `n_bits` of FHE-encrypted keystream and advance the
    /// internal counter. The layout of the result is up to the implementor, 1 bit per
    /// ciphertext for Kreyvium.
    fn next_keystream_bits(
        &mut self,
        sks: &CudaServerKey,
        n_bits: usize,
        streams: &CudaStreams,
    ) -> Result<CudaFheKeyStream, FheKeyStreamError>;

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

        let keystream = self.next_keystream_bits(sks, input.n_bits(), streams)?;
        apply_keystream(sks, &keystream, input, output_layout, streams)
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

    fn transcipher_bool(
        &mut self,
        sks: &CudaServerKey,
        input: &IntegerStreamCiphertext,
        streams: &CudaStreams,
    ) -> Result<CudaBooleanBlock, IntegerTranscipherError> {
        check_kind(input, IntegerStreamCiphertextKind::Boolean)?;
        let layout = input.output_layout(sks.message_modulus)?;
        let blocks = self.transcipher(sks, input.inner(), &layout, streams)?;
        Ok(CudaBooleanBlock::from_cuda_radix_ciphertext(blocks))
    }

    /// Advance the keystream position by `n_bits` without emitting them.
    fn skip(&mut self, sks: &CudaServerKey, n_bits: usize, streams: &CudaStreams);

    fn current_counter(&self) -> u64;
}

/// XOR an FHE-encrypted keystream with a clear symmetric ciphertext.
///
/// GPU counterpart of [crate::transciphering::apply_keystream]. Both run the same CPU code to
/// decide which keystream bits go to which output block and to check the layouts. The backend then
/// builds the output blocks, with one PBS each.
///
/// # Errors
///
/// Those of [crate::transciphering::apply_keystream], plus [TranscipherError::InvalidKeystream] if
/// the LWE dimension of the keystream is not the one of sks, which means another key encrypted it.
pub fn apply_keystream(
    sks: &CudaServerKey,
    keystream: &CudaFheKeyStream,
    input_stream: &StreamCiphertext,
    output_layout: &TranscipheringOutputLayout,
    streams: &CudaStreams,
) -> Result<CudaRadixCiphertext, TranscipherError> {
    let stream_cts = keystream.stream.as_ref();

    // A keystream of another key would panic in the backend
    if stream_cts.d_blocks.lwe_dimension() != sks.bootstrapping_key.output_lwe_dimension() {
        return Err(TranscipherError::InvalidKeystream);
    }

    let plan = StreamApplicationPlan::try_new(
        &keystream.layout,
        keystream.len(),
        input_stream,
        output_layout,
        sks.message_modulus,
        sks.carry_modulus,
        sks.max_noise_level,
    )?;

    // The backend refuses a scratch with no output block
    if plan.contribs().is_empty() {
        let empty: CudaUnsignedRadixCiphertext = sks.create_trivial_zero_radix(0, streams);
        return Ok(empty.into_inner());
    }

    let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &sks.key_switching_key else {
        panic!("Only the standard atomic pattern is supported on GPU")
    };
    let mut output: CudaUnsignedRadixCiphertext =
        sks.create_trivial_zero_radix(plan.contribs().len(), streams);
    unsafe {
        cuda_backend_apply_keystream(
            streams,
            output.as_mut(),
            stream_cts,
            &plan,
            &computing_ks_key.d_vec,
            sks.message_modulus,
            sks.carry_modulus,
            &sks.bootstrapping_key,
            computing_ks_key.params_ffi(),
        );
    }

    Ok(output.into_inner())
}

/// GPU memory [apply_keystream] needs on top of its output, for a keystream with this layout.
///
/// The size depends on the values of the input bits because they set the number of distinct LUTs.
///
/// # Errors
///
/// The errors of [apply_keystream] that do not need the keystream ciphertexts
pub fn get_apply_keystream_size_on_gpu(
    sks: &CudaServerKey,
    keystream_layout: &KeyStreamLayout,
    input_stream: &StreamCiphertext,
    output_layout: &TranscipheringOutputLayout,
    streams: &CudaStreams,
) -> Result<u64, TranscipherError> {
    // apply_keystream takes exactly the cts the input needs
    let bits_per_ct = usize::from(keystream_layout.bits_per_ct().get());
    let plan = StreamApplicationPlan::try_new(
        keystream_layout,
        input_stream.n_bits().div_ceil(bits_per_ct),
        input_stream,
        output_layout,
        sks.message_modulus,
        sks.carry_modulus,
        sks.max_noise_level,
    )?;

    if plan.contribs().is_empty() {
        return Ok(0);
    }

    let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &sks.key_switching_key else {
        panic!("Only the standard atomic pattern is supported on GPU")
    };
    Ok(cuda_backend_get_apply_keystream_size_on_gpu(
        streams,
        &plan,
        sks.message_modulus,
        sks.carry_modulus,
        &sks.bootstrapping_key,
        computing_ks_key.params_ffi(),
    ))
}
