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
/// The keystream must hold at least `input.n_bits()` bits, the unused high bits of its last
/// ciphertext are ignored.
///
/// # Errors
///
/// - [`TranscipherError::InvalidKeystream`] if the keystream does not hold the number of
///   ciphertexts needed for the input, or if its ciphertexts hold more bits than the plaintext
///   space of `sks`
/// - [`TranscipherError::InvalidOutputLayout`] if the output layout does not match the input
///   length, has blocks that do not fit in the message space of `sks`, or has blocks that cannot be
///   built with a linear combination of keystream ciphertexts within the noise budget of `sks`
///   (when a block spans several keystream ciphertexts while using only a part of them)
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

    let plan = StreamApplicationPlan::try_new(
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
#[derive(Debug, PartialEq)]
struct StreamApplicationPlan {
    contribs: Vec<Vec<Contribution>>,
}

impl StreamApplicationPlan {
    /// Build a plan from the keystream and output layouts.
    //
    // The algorithm loops over the entries in the output layout:
    // Example 1:
    // - bits_per_ct = 4, 2_2 params:
    // - output is a list composed of [bool, u4], alignment is 4
    //
    // stream bits:    0   1   2   3   4   5   6   7
    // keystream:      [     ct_0     ][     ct_1     ]
    // output layout:  [Bl][Skip      ][Block ][Block ]
    //
    // entry 0:
    //   - Block(1):
    //     - block_start_bit = 0, block_end_bit = 1
    //     - keystream_bit_pos = 0:
    //       - stream_ct_idx = 0, src_bit_pos = 0, len = 1
    //     => the block is built from ct_0 bits 0..1 (1 Contribution)
    // entry 1:
    //   - Skip(3):
    //     - block_start_bit = 1, block_end_bit = 4
    // entry 2:
    //     - block_start_bit = 4, block_end_bit = 6
    //     - keystream_bit_pos = 4:
    //       - stream_ct_idx = 1, src_bit_pos = 0, len = 2
    //     => the block is built from ct_1 bits 0..2 (1 Contribution)
    // entry 3:
    //     - block_start_bit = 6, block_end_bit = 8
    //     - keystream_bit_pos = 6:
    //       - stream_ct_idx = 1, src_bit_pos = 2, len = 2
    //     => the block is built from ct_1 bits 2..4 (1 Contribution)
    //
    // Example 2:
    // - bits_per_ct = 1, 2_2 params:
    // - output is a list composed of [bool, u4], alignment is 1
    //
    // stream bits:    0   1   2   3   4
    // keystream:      [c0][c1][c2][c3][c4]
    // output layout:  [Bl][Block ][Block ]
    //
    // The difference here is that a block can be built from several keystream cts, one
    // Contribution each
    // entry 0:
    //   - Block(1):
    //     - block_start_bit = 0, block_end_bit = 1
    //     - keystream_bit_pos = 0:
    //       - stream_ct_idx = 0, src_bit_pos = 0, len = 1
    //     => the block is built from c0 bits 0..1 (1 Contribution)
    // entry 1:
    //   - Block(2):
    //     - block_start_bit = 1, block_end_bit = 3
    //     - keystream_bit_pos = 1:
    //       - stream_ct_idx = 1, src_bit_pos = 0, dst_bit_pos = 0, len = 1
    //     - keystream_bit_pos = 2:
    //       - stream_ct_idx = 2, src_bit_pos = 0, dst_bit_pos = 1, len = 1
    //     => the block is built from c1 bits 0..1 and c2 bits 0..1 (2 Contributions)
    // entry 2:
    //   - Block(2):
    //     - block_start_bit = 3, block_end_bit = 5
    //     - keystream_bit_pos = 3:
    //       - stream_ct_idx = 3, src_bit_pos = 0, dst_bit_pos = 0, len = 1
    //     - keystream_bit_pos = 4:
    //       - stream_ct_idx = 4, src_bit_pos = 0, dst_bit_pos = 1, len = 1
    //     => the block is built from c3 bits 0..1 and c4 bits 0..1 (2 Contributions)
    fn try_new(
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

        let mut block_start_bit = 0;
        let mut contribs = Vec::new();
        for output_layout_entry in output_layout.entries().iter() {
            let block_end_bit = block_start_bit + output_layout_entry.len();
            match output_layout_entry {
                TranscipheringOutputLayoutBits::Skip(_) => {} // nothing to do
                TranscipheringOutputLayoutBits::Block(_) => {
                    let mut keystream_bit_pos = block_start_bit;
                    let mut contribs_for_block = Vec::new();
                    while keystream_bit_pos < block_end_bit {
                        let src_bit_pos = keystream_bit_pos % bits_per_ct;
                        let len =
                            (bits_per_ct - src_bit_pos).min(block_end_bit - keystream_bit_pos);
                        let contrib = Contribution {
                            stream_ct_idx: keystream_bit_pos / bits_per_ct,
                            src_bit_pos,
                            dst_bit_pos: keystream_bit_pos - block_start_bit,
                            len,
                            input_bits: user_input
                                .get_bit_range(keystream_bit_pos..keystream_bit_pos + len)
                                .ok_or(TranscipherError::InvalidOutputLayout)?,
                        };
                        contribs_for_block.push(contrib);
                        keystream_bit_pos += len;
                    }

                    contribs.push(contribs_for_block);
                }
            }

            block_start_bit = block_end_bit;
        }

        // Blocks with several contributions are built with a linear combination of the keystream
        // cts. This is not possible if a block uses only a part of a keystream ct while spanning
        // several of them, which can only happen if the output layout is not aligned on the
        // keystream cts.
        for block in contribs.iter().filter(|block| block.len() > 1) {
            if !is_linear_combination_possible(max_noise_level, bits_per_ct, block) {
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
    bits_per_ct: usize,
    contribs: &[Contribution],
) -> bool {
    // dst_bit_pos < block width <= log2(message_modulus), so the shift does not overflow
    let noise_level: u64 = contribs.iter().map(|c| 1u64 << c.dst_bit_pos).sum();

    let fully_consumes_src = |c: &Contribution| c.src_bit_pos == 0 && c.len == bits_per_ct;

    contribs.iter().all(fully_consumes_src) && noise_level <= max_noise_level.get()
}
