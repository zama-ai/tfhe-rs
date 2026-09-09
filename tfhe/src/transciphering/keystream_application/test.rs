use super::*;

use std::num::NonZeroU8;

use crate::shortint::MessageModulus;
use crate::transciphering::StreamCipherKind;

#[test]
fn test_output_layout_push_aligned() {
    use TranscipheringOutputLayoutBits::*;

    let msg_mod = MessageModulus(4);
    let align = nz(8);

    // [u8, bool, u4], aligned on 8 bits
    let mut layout = TranscipheringOutputLayout::new();
    layout
        .push_aligned(TranscipheringOutputLayout::radix(8, msg_mod), align)
        .push_aligned(TranscipheringOutputLayout::boolean(), align)
        .push_aligned(TranscipheringOutputLayout::radix(4, msg_mod), align);

    assert_eq!(
        layout.layout,
        vec![
            Block(nz(2)),
            Block(nz(2)),
            Block(nz(2)),
            Block(nz(2)),
            Block(nz(1)),
            Skip(nz(7)),
            Block(nz(2)),
            Block(nz(2)),
            Skip(nz(4)),
        ]
    );
    assert_eq!(layout.bit_length(), 24);

    // An alignment of 1 never adds padding
    let mut layout = TranscipheringOutputLayout::new();
    layout
        .push_aligned(TranscipheringOutputLayout::boolean(), nz(1))
        .push_aligned(TranscipheringOutputLayout::radix(13, msg_mod), nz(1));
    assert_eq!(layout, output_layout(&[1, 2, 2, 2, 2, 2, 2, 1]));
}

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Message modulus used to build plans in the clear tests, large enough for all the block widths
/// used in these tests
const TEST_PLAN_MSG_MOD: MessageModulus = MessageModulus(1 << 8);

fn nz(v: u8) -> NonZeroU8 {
    NonZeroU8::new(v).unwrap()
}

/// An output layout made of blocks of the given widths, without skipped bits
fn output_layout(widths: &[u8]) -> TranscipheringOutputLayout {
    TranscipheringOutputLayout {
        layout: widths
            .iter()
            .map(|w| TranscipheringOutputLayoutBits::Block(nz(*w)))
            .collect(),
    }
}

fn keystream_layout(bits_per_ct: u8) -> KeyStreamLayout {
    KeyStreamLayout::try_new(nz(bits_per_ct)).unwrap()
}

fn stream_ciphertext(bytes: Vec<u8>, n_bits: usize) -> StreamCiphertext {
    assert_eq!(bytes.len(), n_bits.div_ceil(8));
    StreamCiphertext {
        kind: StreamCipherKind::Dynamic,
        encryption_counter: 0,
        n_bits,
        bytes,
    }
}

/// Random LSB-first bits, with the unused bits of the last byte set to 0
fn random_bits(rng: &mut impl Rng, n_bits: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..n_bits.div_ceil(8)).map(|_| rng.gen()).collect();
    if !n_bits.is_multiple_of(8) {
        *bytes.last_mut().unwrap() &= (1u8 << (n_bits % 8)) - 1;
    }
    bytes
}

/// LSB-first bit `i` of `bytes` (i.e. `bytes[i / 8] >> (i % 8) & 1`).
fn bit_at(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (i % 8)) & 1
}

/// Reads `len` LSB-first bits of `bytes` starting at `start`, one bit at a time
fn read_bits(bytes: &[u8], start: usize, len: usize) -> u64 {
    assert!(len <= 64);
    (0..len).fold(0, |acc, i| acc | (u64::from(bit_at(bytes, start + i)) << i))
}

/// Split the "FHE clear" input keystream bits in blocks according to the provided layout.
/// `keystream_bits` must hold `layout.bit_length(ct_count)` bits.
fn clear_keystream_blocks(
    keystream_bits: &[u8],
    layout: &KeyStreamLayout,
    ct_count: usize,
) -> Vec<u64> {
    let bits_per_ct = layout.bits_per_ct.get() as usize;
    (0..ct_count)
        .map(|idx| read_bits(keystream_bits, idx * bits_per_ct, bits_per_ct))
        .collect()
}

/// Expected output blocks: `input ^ keystream`, split according to the output layout. Skipped
/// bits produce no output.
fn expected_blocks(
    input_bits: &[u8],
    keystream_bits: &[u8],
    output_layout: &TranscipheringOutputLayout,
) -> Vec<u64> {
    let mut start = 0;
    output_layout
        .layout
        .iter()
        .filter_map(|entry| {
            let width = entry.len();
            let value = match entry {
                TranscipheringOutputLayoutBits::Block(_) => Some(
                    read_bits(input_bits, start, width) ^ read_bits(keystream_bits, start, width),
                ),
                TranscipheringOutputLayoutBits::Skip(_) => None,
            };
            start += width;
            value
        })
        .collect()
}

/// Widths of the output blocks of a layout, skipped bits excluded
fn block_widths(output_layout: &TranscipheringOutputLayout) -> Vec<usize> {
    output_layout
        .layout
        .iter()
        .filter_map(|entry| match entry {
            TranscipheringOutputLayoutBits::Block(w) => Some(w.get() as usize),
            TranscipheringOutputLayoutBits::Skip(_) => None,
        })
        .collect()
}

/// For each stream bit, whether the output layout skips it
fn skipped_bits(output_layout: &TranscipheringOutputLayout) -> Vec<bool> {
    output_layout
        .layout
        .iter()
        .flat_map(|entry| {
            let skipped = matches!(entry, TranscipheringOutputLayoutBits::Skip(_));
            std::iter::repeat_n(skipped, entry.len())
        })
        .collect()
}

/// A random output layout, either made of arbitrary blocks and skips, or of typed parts padded
/// to an alignment like in an input package
fn random_output_layout(rng: &mut impl Rng) -> TranscipheringOutputLayout {
    use TranscipheringOutputLayoutBits::*;

    if rng.gen_bool(0.5) {
        // Blocks of 1 to 4 bits, mixing widths to cover booleans in the middle, and skips
        let n_entries = rng.gen_range(0..=24);
        TranscipheringOutputLayout {
            layout: (0..n_entries)
                .map(|_| {
                    if rng.gen_bool(0.25) {
                        Skip(nz(rng.gen_range(1..=8)))
                    } else {
                        Block(nz(rng.gen_range(1..=4)))
                    }
                })
                .collect(),
        }
    } else {
        // Booleans and integers, with 1 to 4 bits per block, each part aligned on 1 to 8 bits
        let msg_mod = MessageModulus(1 << rng.gen_range(1..=4));
        let alignment = nz(1 << rng.gen_range(0..=3));
        let mut layout = TranscipheringOutputLayout::new();
        for _ in 0..rng.gen_range(0..=6) {
            let part = if rng.gen_bool(0.3) {
                TranscipheringOutputLayout::boolean()
            } else {
                TranscipheringOutputLayout::radix(rng.gen_range(1..=16), msg_mod)
            };
            layout.push_aligned(part, alignment);
        }
        layout
    }
}

/// A typed input part
enum Part {
    Bool,
    Radix(usize),
}

/// The layout of a list of parts, each one aligned on 8 bits like in an input package
fn aligned_parts(parts: &[Part], msg_mod: MessageModulus) -> TranscipheringOutputLayout {
    let mut layout = TranscipheringOutputLayout::new();
    for part in parts {
        let part_layout = match part {
            Part::Bool => TranscipheringOutputLayout::boolean(),
            Part::Radix(n_bits) => TranscipheringOutputLayout::radix(*n_bits, msg_mod),
        };
        layout.push_aligned(part_layout, nz(8));
    }
    layout
}

/// Runs the plan in the clear, mirroring what `build_block` does under FHE
fn simulate_plan(plan: &StreamApplicationPlan, keystream_cts: &[u64]) -> Vec<u64> {
    plan.contribs
        .iter()
        .map(|block| {
            if let [c] = block.as_slice() {
                c.extract_xor(keystream_cts[c.stream_ct_idx])
            } else {
                // Raw keystream cts, the whole value scaled by 2^dst, as in the FHE linear
                // combination. A contribution wrongly flagged as fully consuming its ct would bring
                // extra bits here and fail the comparison.
                let packed: u64 = block
                    .iter()
                    .map(|c| keystream_cts[c.stream_ct_idx] << c.dst_bit_pos)
                    .sum();
                Contribution::packed_xor(block, packed)
            }
        })
        .collect()
}

#[test]
fn test_get_bit_range() {
    let seed: u64 = rand::thread_rng().gen();
    let mut rng = StdRng::seed_from_u64(seed);
    let n_bits = 157;
    let ct = stream_ciphertext(random_bits(&mut rng, n_bits), n_bits);

    for start in 0..=n_bits {
        for end in start..=(start + 8).min(n_bits) {
            let range = start..end;
            let in_one_byte = range.is_empty() || start / 8 == (end - 1) / 8;
            assert_eq!(
                ct.get_bit_range(range),
                in_one_byte.then(|| read_bits(&ct.bytes, start, end - start)),
                "seed={seed}, range {start}..{end}"
            );
        }
    }

    #[allow(clippy::reversed_empty_ranges)]
    let reversed = 5..3;
    assert!(ct.get_bit_range(reversed).is_none());
    // Out of bounds, including in the last byte that holds only 5 bits
    assert!(ct.get_bit_range(155..158).is_none());
    assert!(ct.get_bit_range(158..158).is_none());
    assert_eq!(ct.get_bit_range(157..157), Some(0));
}

#[test]
fn test_output_layout_radix() {
    let widths = |layout: TranscipheringOutputLayout| -> Vec<u8> {
        layout
            .layout
            .iter()
            .map(|entry| match entry {
                TranscipheringOutputLayoutBits::Block(w) => w.get(),
                TranscipheringOutputLayoutBits::Skip(_) => panic!("radix should not skip bits"),
            })
            .collect()
    };

    assert!(widths(TranscipheringOutputLayout::radix(0, MessageModulus(4))).is_empty());
    assert_eq!(
        widths(TranscipheringOutputLayout::radix(16, MessageModulus(4))),
        vec![2; 8]
    );
    assert_eq!(
        widths(TranscipheringOutputLayout::radix(13, MessageModulus(4))),
        vec![2, 2, 2, 2, 2, 2, 1]
    );
    assert_eq!(
        widths(TranscipheringOutputLayout::radix(8, MessageModulus(8))),
        vec![3, 3, 2]
    );
    assert_eq!(
        widths(TranscipheringOutputLayout::radix(3, MessageModulus(2))),
        vec![1, 1, 1]
    );
}

/// The plan checks its own preconditions, and returns an error instead of panicking
#[test]
fn test_plan_errors() {
    // 8 input bits, with 4 bits per keystream ct
    let input = stream_ciphertext(vec![0], 8);
    let msg_mod = MessageModulus(4);
    let max_noise_level = MaxNoiseLevel::new(5);

    assert!(StreamApplicationPlan::try_new(
        &keystream_layout(4),
        2,
        &input,
        &output_layout(&[2; 4]),
        msg_mod,
        max_noise_level,
    )
    .is_ok());

    // Not enough, or too many keystream cts
    for ct_count in [1, 3] {
        assert_eq!(
            StreamApplicationPlan::try_new(
                &keystream_layout(4),
                ct_count,
                &input,
                &output_layout(&[2; 4]),
                msg_mod,
                max_noise_level,
            ),
            Err(TranscipherError::InvalidKeystream)
        );
    }

    // Output layout shorter or longer than the input
    for widths in [&[2; 3][..], &[2; 5][..]] {
        assert_eq!(
            StreamApplicationPlan::try_new(
                &keystream_layout(4),
                2,
                &input,
                &output_layout(widths),
                msg_mod,
                max_noise_level,
            ),
            Err(TranscipherError::InvalidOutputLayout)
        );
    }

    // Output blocks that do not fit in the message space
    assert_eq!(
        StreamApplicationPlan::try_new(
            &keystream_layout(4),
            2,
            &input,
            &output_layout(&[4, 4]),
            msg_mod,
            max_noise_level,
        ),
        Err(TranscipherError::InvalidOutputLayout)
    );

    // A block that spans two keystream cts while using only a part of them cannot be built with a
    // linear combination
    // |0 1 2 3|4 5 6 7| -> |0|1 2|3 4|5 6|7|: block 2 (bits 3..5) straddles both cts
    assert_eq!(
        StreamApplicationPlan::try_new(
            &keystream_layout(4),
            2,
            &input,
            &output_layout(&[1, 2, 2, 2, 1]),
            msg_mod,
            max_noise_level,
        ),
        Err(TranscipherError::InvalidOutputLayout)
    );

    // 1-bit keystream into 2-bit blocks: the linear combination needs a noise budget of 1 + 2
    assert!(StreamApplicationPlan::try_new(
        &KeyStreamLayout::single_bit(),
        8,
        &input,
        &output_layout(&[2; 4]),
        msg_mod,
        MaxNoiseLevel::new(3),
    )
    .is_ok());
    assert_eq!(
        StreamApplicationPlan::try_new(
            &KeyStreamLayout::single_bit(),
            8,
            &input,
            &output_layout(&[2; 4]),
            msg_mod,
            MaxNoiseLevel::new(2),
        ),
        Err(TranscipherError::InvalidOutputLayout)
    );
}

#[test]
fn test_plan_known_layouts() {
    let msg_mod = MessageModulus(4);
    let max_noise_level = MaxNoiseLevel::new(5);

    // 4 bits per keystream ct, [bool, u4] aligned on 4 bits: [B1, S3, B2, B2]. A block in the
    // middle of a keystream ct, and two blocks from the same keystream ct.
    let mut layout = TranscipheringOutputLayout::new();
    layout
        .push_aligned(TranscipheringOutputLayout::boolean(), nz(4))
        .push_aligned(TranscipheringOutputLayout::radix(4, msg_mod), nz(4));
    assert_eq!(
        StreamApplicationPlan::try_new(
            &keystream_layout(4),
            2,
            &stream_ciphertext(vec![0b1011_0110], 8),
            &layout,
            TEST_PLAN_MSG_MOD,
            max_noise_level,
        ),
        Ok(StreamApplicationPlan {
            contribs: vec![
                vec![Contribution {
                    stream_ct_idx: 0,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 1,
                    input_bits: 0b0,
                }],
                vec![Contribution {
                    stream_ct_idx: 1,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b11,
                }],
                vec![Contribution {
                    stream_ct_idx: 1,
                    src_bit_pos: 2,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b10,
                }],
            ],
        })
    );

    // 1 bit per keystream ct, [bool, u4] aligned on 1 bit: [B1, B2, B2]. Blocks are packed from
    // several keystream cts.
    let mut layout = TranscipheringOutputLayout::new();
    layout
        .push_aligned(TranscipheringOutputLayout::boolean(), nz(1))
        .push_aligned(TranscipheringOutputLayout::radix(4, msg_mod), nz(1));
    assert_eq!(
        StreamApplicationPlan::try_new(
            &KeyStreamLayout::single_bit(),
            5,
            &stream_ciphertext(vec![0b1_0110], 5),
            &layout,
            TEST_PLAN_MSG_MOD,
            max_noise_level,
        ),
        Ok(StreamApplicationPlan {
            contribs: vec![
                vec![Contribution {
                    stream_ct_idx: 0,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 1,
                    input_bits: 0b0,
                }],
                vec![
                    Contribution {
                        stream_ct_idx: 1,
                        src_bit_pos: 0,
                        dst_bit_pos: 0,
                        len: 1,
                        input_bits: 0b1,
                    },
                    Contribution {
                        stream_ct_idx: 2,
                        src_bit_pos: 0,
                        dst_bit_pos: 1,
                        len: 1,
                        input_bits: 0b1,
                    },
                ],
                vec![
                    Contribution {
                        stream_ct_idx: 3,
                        src_bit_pos: 0,
                        dst_bit_pos: 0,
                        len: 1,
                        input_bits: 0b0,
                    },
                    Contribution {
                        stream_ct_idx: 4,
                        src_bit_pos: 0,
                        dst_bit_pos: 1,
                        len: 1,
                        input_bits: 0b1,
                    },
                ],
            ],
        })
    );

    // 2 bits per keystream ct into a 4-bit block: packed with a scalar of 4 for the second ct
    assert_eq!(
        StreamApplicationPlan::try_new(
            &keystream_layout(2),
            2,
            &stream_ciphertext(vec![0b1001], 4),
            &output_layout(&[4]),
            TEST_PLAN_MSG_MOD,
            max_noise_level,
        ),
        Ok(StreamApplicationPlan {
            contribs: vec![vec![
                Contribution {
                    stream_ct_idx: 0,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b01,
                },
                Contribution {
                    stream_ct_idx: 1,
                    src_bit_pos: 0,
                    dst_bit_pos: 2,
                    len: 2,
                    input_bits: 0b10,
                },
            ],],
        })
    );

    // 4 bits per keystream ct and 6 input bits: the last keystream ct is only partially used
    assert_eq!(
        StreamApplicationPlan::try_new(
            &keystream_layout(4),
            2,
            &stream_ciphertext(vec![0b10_0111], 6),
            &output_layout(&[2, 2, 2]),
            TEST_PLAN_MSG_MOD,
            max_noise_level,
        ),
        Ok(StreamApplicationPlan {
            contribs: vec![
                vec![Contribution {
                    stream_ct_idx: 0,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b11,
                }],
                vec![Contribution {
                    stream_ct_idx: 0,
                    src_bit_pos: 2,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b01,
                }],
                vec![Contribution {
                    stream_ct_idx: 1,
                    src_bit_pos: 0,
                    dst_bit_pos: 0,
                    len: 2,
                    input_bits: 0b10,
                }],
            ],
        })
    );
}

/// Builds plans for random keystream and output layouts, checks their structural invariants,
/// and checks that running them in the clear gives `input ^ keystream`.
#[test]
fn test_plan_random_layouts() {
    let seed: u64 = rand::thread_rng().gen();
    let mut rng = StdRng::seed_from_u64(seed);

    'testcase: for iter in 0..1000 {
        let ctx = format!("seed={seed}, iter={iter}");

        let output_layout = random_output_layout(&mut rng);
        let widths = block_widths(&output_layout);
        let skipped = skipped_bits(&output_layout);
        let n_bits = output_layout.bit_length();

        // Keystream cts of 1, 2, 4 or 8 bits. The last one may be partially used, its unused high
        // bits are random and must be ignored.
        let bits_per_ct = 1 << rng.gen_range(0..=3u8);
        let stream_layout = keystream_layout(bits_per_ct);
        let bits_per_ct = bits_per_ct as usize;
        let ct_count = n_bits.div_ceil(bits_per_ct);
        let keystream_len = stream_layout.bit_length(ct_count);

        let input_bits = random_bits(&mut rng, n_bits);
        let keystream_bits = random_bits(&mut rng, keystream_len);
        let input = stream_ciphertext(input_bits.clone(), n_bits);

        // 1-bit keystreams into 4-bit blocks need a noise budget of 15, so the drawn budget
        // produces both accepted and refused layouts
        let max_noise_level = MaxNoiseLevel::new(rng.gen_range(1..=16));
        let plan = StreamApplicationPlan::try_new(
            &stream_layout,
            ct_count,
            &input,
            &output_layout,
            TEST_PLAN_MSG_MOD,
            max_noise_level,
        );

        // A block can be built if it is contained in a single keystream ct, or if it is made of
        // full keystream cts whose linear combination fits in the noise budget
        let mut block_start = 0;
        for entry in &output_layout.layout {
            let len = entry.len();
            if let TranscipheringOutputLayoutBits::Block(_) = entry {
                let in_one_ct = block_start / bits_per_ct == (block_start + len - 1) / bits_per_ct;
                let full_cts = block_start % bits_per_ct == 0 && len % bits_per_ct == 0;
                let noise: u64 = (0..len / bits_per_ct)
                    .map(|k| 1u64 << (k * bits_per_ct))
                    .sum();
                if !(in_one_ct || (full_cts && noise <= max_noise_level.get())) {
                    assert_eq!(
                        plan.err(),
                        Some(TranscipherError::InvalidOutputLayout),
                        "{ctx}"
                    );
                    continue 'testcase;
                }
            }
            block_start += len;
        }

        let plan = plan.unwrap_or_else(|err| panic!("{ctx}: unexpected error {err:?}"));
        let n_blocks = output_layout
            .layout
            .iter()
            .filter(|entry| matches!(entry, TranscipheringOutputLayoutBits::Block(_)))
            .count();
        assert_eq!(plan.contribs.len(), n_blocks, "{ctx}");

        // Structural invariants: contributions fit in their src and dst cts, every output bit is
        // written exactly once, and every keystream bit is used exactly once, except the skipped
        // ones and the ones past the input length that are never used
        let mut ks_bit_used = vec![false; keystream_len];
        for (block_idx, block) in plan.contribs.iter().enumerate() {
            let mut dst_bit_used = vec![false; widths[block_idx]];
            for c in block {
                assert!(c.len > 0, "{ctx}");
                assert!(c.src_bit_pos + c.len <= bits_per_ct, "{ctx}");
                assert!(c.dst_bit_pos + c.len <= widths[block_idx], "{ctx}");

                for i in 0..c.len {
                    let ks_bit = c.stream_ct_idx * bits_per_ct + c.src_bit_pos + i;
                    assert!(!ks_bit_used[ks_bit], "{ctx}: keystream bit {ks_bit} reused");
                    ks_bit_used[ks_bit] = true;

                    let dst_bit = c.dst_bit_pos + i;
                    assert!(
                        !dst_bit_used[dst_bit],
                        "{ctx}: bit {dst_bit} of block {block_idx} written twice"
                    );
                    dst_bit_used[dst_bit] = true;
                }
            }
            assert!(
                dst_bit_used.iter().all(|b| *b),
                "{ctx}: block {block_idx} not fully written"
            );
        }
        for (bit, used) in ks_bit_used.iter().enumerate() {
            let expected_used = bit < n_bits && !skipped[bit];
            assert_eq!(
                *used, expected_used,
                "{ctx}: keystream bit {bit} used={used}, expected {expected_used}"
            );
        }

        // Functional check
        let keystream_cts = clear_keystream_blocks(&keystream_bits, &stream_layout, ct_count);
        assert_eq!(
            simulate_plan(&plan, &keystream_cts),
            expected_blocks(&input_bits, &keystream_bits, &output_layout),
            "{ctx}"
        );
    }
}

/// Checks which path `build_block` takes for blocks with several contributions, at the noise
/// budget of the 2_2 parameters. Guards against a silent fallback to the more expensive extraction
/// path.
#[test]
fn test_linear_combination_choice() {
    use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let max_noise_level = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.max_noise_level;

    let plan_blocks = |stream_layout: KeyStreamLayout,
                       ct_count: usize,
                       output_layout: &TranscipheringOutputLayout| {
        let n_bits = output_layout.bit_length();
        let input = stream_ciphertext(vec![0; n_bits.div_ceil(8)], n_bits);
        StreamApplicationPlan::try_new(
            &stream_layout,
            ct_count,
            &input,
            output_layout,
            TEST_PLAN_MSG_MOD,
            // The plans are built without noise limit to check the linear combination below
            MaxNoiseLevel::new(u64::MAX),
        )
        .unwrap()
        .contribs
    };

    // 1-bit keystream into 2-bit blocks: linear, with a noise of 1 + 2. This is the path of the
    // single bit stream ciphers.
    for block in plan_blocks(KeyStreamLayout::single_bit(), 8, &output_layout(&[2; 4])) {
        assert!(is_linear_combination_possible(max_noise_level, 1, &block));
    }

    // 1-bit keystream into a 4-bit block: 1 + 2 + 4 + 8 exceeds the budget
    let blocks = plan_blocks(KeyStreamLayout::single_bit(), 4, &output_layout(&[4]));
    assert!(!is_linear_combination_possible(
        max_noise_level,
        1,
        &blocks[0]
    ));

    // 2-bit keystream into a 4-bit block: linear, with a noise of 1 + 4
    let blocks = plan_blocks(keystream_layout(2), 2, &output_layout(&[4]));
    assert!(is_linear_combination_possible(
        max_noise_level,
        2,
        &blocks[0]
    ));
}

/// Runs `apply_keystream` under FHE on keystreams with several bits per ct, which the
/// ciphers' tests (all single-bit) do not cover. The "keystream" is created by generating
/// and encrypting random bits.
#[test]
fn test_apply_keystream_fhe() {
    use crate::shortint::ciphertext::{Degree, NoiseLevel};
    use crate::shortint::gen_keys;
    use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let (cks, sks) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let msg_mod = sks.message_modulus;
    let carry_mod = sks.carry_modulus;

    let seed: u64 = rand::thread_rng().gen();
    let mut rng = StdRng::seed_from_u64(seed);

    // Each case covers a different path of `build_block`, don't remove one without checking that
    // its path is covered elsewhere
    let cases: Vec<(&str, KeyStreamLayout, TranscipheringOutputLayout)> = vec![
        // 14 bits with 4 bits per keystream ct: the last keystream ct is partially used, its
        // unused high bits are random and must be ignored
        (
            "4 bits keystream, radix of 14 bits",
            KeyStreamLayout::full_space(msg_mod, carry_mod).unwrap(),
            TranscipheringOutputLayout::radix(14, msg_mod),
        ),
        // Byte aligned parts, like in an input package: single contributions, from keystream cts
        // that are partially skipped (the bool's) or fully skipped (the ct after the bool)
        (
            "4 bits keystream, [u8, bool, u4] aligned on 8",
            KeyStreamLayout::full_space(msg_mod, carry_mod).unwrap(),
            aligned_parts(&[Part::Radix(8), Part::Bool, Part::Radix(4)], msg_mod),
        ),
        // Single contributions that fully consume their keystream ct, as produced by the current
        // OPRF with 2_2 parameters
        (
            "2 bits keystream, [bool, u16, bool] aligned on 8",
            keystream_layout(2),
            aligned_parts(&[Part::Bool, Part::Radix(16), Part::Bool], msg_mod),
        ),
        // Linear combination path for the u8 blocks, single contribution for the bool, and
        // skipped 1-bit keystream cts
        (
            "single bit keystream, [bool, u8] aligned on 8",
            KeyStreamLayout::single_bit(),
            aligned_parts(&[Part::Bool, Part::Radix(8)], msg_mod),
        ),
    ];

    for (name, stream_layout, output_layout) in cases {
        let ctx = format!("{name} (seed={seed})");

        let n_bits = output_layout.bit_length();
        let ct_count = n_bits.div_ceil(stream_layout.bits_per_ct.get() as usize);

        // If n_bits is not a multiple of the ct width, the last keystream ct holds random unused
        // bits
        let input_bits = random_bits(&mut rng, n_bits);
        let keystream_bits = random_bits(&mut rng, stream_layout.bit_length(ct_count));

        // Keystream values can use the full message + carry space. `unchecked_encrypt` always
        // sets the maximum degree, so the actual bound is set to respect the keystream contract.
        let keystream_degree = Degree::new((1 << stream_layout.bits_per_ct.get()) - 1);
        let keystream = FheKeyStream::try_new(
            clear_keystream_blocks(&keystream_bits, &stream_layout, ct_count)
                .into_iter()
                .map(|v| {
                    let mut ct = cks.unchecked_encrypt(v);
                    ct.degree = keystream_degree;
                    ct
                })
                .collect(),
            stream_layout,
        )
        .unwrap();
        let input = stream_ciphertext(input_bits.clone(), n_bits);

        let output = apply_keystream(&sks, &keystream, &input, &output_layout).unwrap();

        let expected = expected_blocks(&input_bits, &keystream_bits, &output_layout);
        let widths = block_widths(&output_layout);
        assert_eq!(output.len(), expected.len(), "{ctx}");
        for (i, ((ct, expected), width)) in output.iter().zip(expected).zip(widths).enumerate() {
            assert_eq!(
                cks.decrypt_message_and_carry(ct),
                expected,
                "{ctx}: block {i}"
            );
            assert_eq!(ct.noise_level(), NoiseLevel::NOMINAL, "{ctx}: block {i}");
            // The degree is bounded by the block width, so for example a boolean has a degree of
            // at most 1. This also implies that the carries are empty.
            assert!(
                ct.degree.get() < 1 << width,
                "{ctx}: block {i} of width {width} has degree {:?}",
                ct.degree
            );
        }
    }

    // A keystream layout with more bits per ct than the plaintext space of the key is rejected
    let mut ct = cks.unchecked_encrypt(0);
    ct.degree = Degree::new((1 << 8) - 1);
    let keystream = FheKeyStream::try_new(vec![ct], keystream_layout(8)).unwrap();
    let input = stream_ciphertext(vec![0], 8);
    assert_eq!(
        apply_keystream(
            &sks,
            &keystream,
            &input,
            &TranscipheringOutputLayout::radix(8, msg_mod)
        ),
        Err(TranscipherError::InvalidKeystream)
    );
}
