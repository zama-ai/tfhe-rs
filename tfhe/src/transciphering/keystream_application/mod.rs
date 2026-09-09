use rayon::prelude::*;

use crate::shortint::{Ciphertext, MaxNoiseLevel, MessageModulus, ServerKey};
use crate::transciphering::{
    FheKeyStream, KeyStreamLayout, StreamCiphertext, TranscipheringOutputLayout,
};

use super::{TranscipherError, TranscipheringOutputLayoutBits};

#[cfg(test)]
mod test;

/// Xor an FHE keystream with a clear [`StreamCiphertext`], and produce ciphertexts following the
/// provided [`TranscipheringOutputLayout`].
///
/// The keystream must hold `input.n_bits()` bits, the unused high bits of its last ciphertext
/// are ignored.
pub fn apply_keystream(
    sks: &ServerKey,
    keystream: &FheKeyStream,
    input: &StreamCiphertext,
    output_layout: &TranscipheringOutputLayout,
) -> Result<Vec<Ciphertext>, TranscipherError> {
    if !keystream
        .layout
        .can_fit(sks.message_modulus, sks.carry_modulus)
    {
        return Err(TranscipherError::InvalidKeystream);
    }

    let plan = StreamApplicationPlan::new(
        &keystream.layout,
        keystream.len(),
        input,
        output_layout,
        sks.message_modulus,
        sks.max_noise_level,
    )?;

    Ok(plan.apply(sks, keystream))
}

/// Contribution of one keystream ct to one output ct
#[derive(Clone, Debug, PartialEq)]
struct Contribution {
    /// The index of the stream ct of this contribution in the keystream
    stream_ct_idx: usize,
    /// The starting bit position of this contribution in the keystream ct
    src_bit_pos: usize,
    /// The starting bit position of this contribution in the output ct
    dst_bit_pos: usize,
    /// The number of bits that will be applied by this contribution
    len: usize,
    /// The "FHE clear" user input bits for this contribution, that will be
    /// xor'ed with the keystream.
    input_bits: u64,
    /// Is this contribution fully consuming the src stream ct? If that's the case, the stream ct
    /// can be used as is in a linear combination.
    fully_consumes_src: bool,
}

impl Contribution {
    /// Function for the lookup table associated with this contribution, that extract the stream
    /// bits from the ct, and xor them with the input to produce the output.
    fn extract_xor(&self, stream_bits: u64) -> u64 {
        (((stream_bits >> self.src_bit_pos) ^ self.input_bits) & ((1 << self.len) - 1))
            << self.dst_bit_pos
    }

    /// Function for the lookup table associated with the contributions that will contribute
    /// to a single output ct. It can be used to xor user input bits with a ct that is already
    /// packed from multiple stream cts.
    fn packed_xor(contribs: &[Self], packed_stream_bits: u64) -> u64 {
        let input_combined = contribs
            .iter()
            .fold(0, |acc, c| acc | (c.input_bits << c.dst_bit_pos));
        let width: usize = contribs.iter().map(|c| c.len).sum();
        (packed_stream_bits ^ input_combined) & ((1 << width) - 1)
    }
}

/// The mapping between the keystream ct and the output ct
///
/// The outer vec has one element per output ct.
/// The inner vecs have one element per keystream ct that will "contribute" to this output ct.
///
/// Examples:
/// with 4bits per stream ct and 2_2 params:
/// keystream layout is: [bbbb] [bbbb]
/// output layout is:    [bb] [bb] [bb] [bb]
/// - CT0 of the output is built from CT0 bits 0 and 1 of the keystream
/// - CT1 of the output is built from CT0 bits 2 and 3 of the keystream
/// - CT2 of the output is built from CT1 bits 0 and 1 of the keystream
/// - CT3 of the output is built from CT1 bits 2 and 3 of the keystream
///
/// with 1 bit per stream ct and 2_2 params:
/// keystream layout is: [b] [b] [b] [b]
/// output layout is:    [bb] [bb]
/// - CT0 of the output is built from CT0 bit 0 and CT1 bit 0 of the keystream
/// - CT1 of the output is built from CT2 bit 0 and CT3 bit 0 of the keystream
///
/// This is basically what this type is expressing.
/// Once we have this, keystream application becomes a dumb operation, with a single pbs per
/// output block:
/// - one contribution: extract the bits from the keystream ct and xor them with the user input
/// - several contributions: pack the keystream cts with a linear combination, then xor with the
///   user input
struct StreamApplicationPlan {
    contribs: Vec<Vec<Contribution>>,
}

impl StreamApplicationPlan {
    /// Build a plan from the keystream and output layouts.
    fn new(
        stream_layout: &KeyStreamLayout,
        ct_count: usize,
        user_input: &StreamCiphertext,
        output_layout: &TranscipheringOutputLayout,
        message_modulus: MessageModulus,
        max_noise_level: MaxNoiseLevel,
    ) -> Result<Self, TranscipherError> {
        let n_bits = user_input.n_bits;
        let bits_per_ct = usize::from(stream_layout.bits_per_ct.get());

        if ct_count != n_bits.div_ceil(bits_per_ct) {
            return Err(TranscipherError::InvalidKeystream);
        }

        output_layout.validate(n_bits, message_modulus)?;

        let mut block_start = 0;
        let mut contribs = Vec::new();
        for layout_entry in output_layout.entries().iter() {
            let block_end = block_start + layout_entry.len();
            match layout_entry {
                TranscipheringOutputLayoutBits::Skip(_) => {} // nothing to do
                TranscipheringOutputLayoutBits::Block(_) => {
                    let mut keystream_pos = block_start;
                    let mut contribs_for_block = Vec::new();
                    while keystream_pos < block_end {
                        let src_bit_pos = keystream_pos % bits_per_ct;
                        let len = (bits_per_ct - src_bit_pos).min(block_end - keystream_pos);
                        let contrib = Contribution {
                            stream_ct_idx: keystream_pos / bits_per_ct,
                            src_bit_pos,
                            dst_bit_pos: keystream_pos - block_start,
                            len,
                            input_bits: user_input
                                .get_bit_range(keystream_pos..keystream_pos + len)
                                .ok_or(TranscipherError::InvalidOutputLayout)?,
                            fully_consumes_src: src_bit_pos == 0 && len == bits_per_ct,
                        };
                        contribs_for_block.push(contrib);
                        keystream_pos += len;
                    }

                    contribs.push(contribs_for_block);
                }
            }

            block_start = block_end;
        }

        // Blocks with several contributions are built with a linear combination of the keystream
        // cts. This is not possible if a block uses only a part of a keystream ct while spanning
        // several of them, which can only happen if the output layout is not aligned on the
        // keystream cts.
        for block in contribs.iter().filter(|block| block.len() > 1) {
            if !is_linear_combination_possible(max_noise_level, block) {
                return Err(TranscipherError::InvalidOutputLayout);
            }
        }

        Ok(Self { contribs })
    }

    fn apply(self, sks: &ServerKey, keystream: &FheKeyStream) -> Vec<Ciphertext> {
        self.contribs
            .par_iter()
            .map(|out_ct_contribs| build_block(sks, keystream, out_ct_contribs))
            .collect()
    }
}

/// Extract the needed bits from the keystream ciphertext, and xor it with the user input bits to
/// produce the output ciphertext, using a single pbs.
///
/// This can be used if the output ciphertext comes from a single contribution.
fn extract_xor_keystream(
    sks: &ServerKey,
    keystream: &FheKeyStream,
    contrib: &Contribution,
) -> Ciphertext {
    let lut = sks.generate_lookup_table(|x| contrib.extract_xor(x));
    sks.apply_lookup_table(&keystream.stream[contrib.stream_ct_idx], &lut)
}

/// For a list of contributions that produce a single output ciphertext, this will pack the
/// keystream ciphertexts with a linear combination and xor the result with the user input, using a
/// single pbs.
///
/// The plan only produces blocks with several contributions if they can be built this way.
fn pack_xor_keystream(
    sks: &ServerKey,
    keystream: &FheKeyStream,
    contribs: &[Contribution],
) -> Ciphertext {
    let packed = contribs.iter().fold(sks.create_trivial(0), |acc, c| {
        // The plan checked that the sum of the scalars fits in the noise budget, which is far
        // below 256
        let scalar =
            u8::try_from(1u64 << c.dst_bit_pos).expect("scalar is bounded by the noise budget");
        sks.unchecked_add(
            &acc,
            &sks.unchecked_scalar_mul(&keystream.stream[c.stream_ct_idx], scalar),
        )
    });

    let lut = sks.generate_lookup_table(|x| Contribution::packed_xor(contribs, x));
    sks.apply_lookup_table(&packed, &lut)
}

fn build_block(sks: &ServerKey, keystream: &FheKeyStream, contribs: &[Contribution]) -> Ciphertext {
    if let [contrib] = contribs {
        return extract_xor_keystream(sks, keystream, contrib);
    }

    pack_xor_keystream(sks, keystream, contribs)
}

/// Returns true if it's possible to pack the keystream ciphertexts to match the output layout
/// without pbs.
///
/// That's the case if the contributions "consume" the full input keystream ciphertexts on their
/// own (no extraction is needed), and the noise budget is sufficient to sum them all.
fn is_linear_combination_possible(
    max_noise_level: MaxNoiseLevel,
    contribs: &[Contribution],
) -> bool {
    // dst_bit_pos < block width <= log2(message_modulus), so the shift does not overflow
    let noise_level: u64 = contribs.iter().map(|c| 1u64 << c.dst_bit_pos).sum();

    contribs.iter().all(|c| c.fully_consumes_src) && noise_level <= max_noise_level.get()
}
