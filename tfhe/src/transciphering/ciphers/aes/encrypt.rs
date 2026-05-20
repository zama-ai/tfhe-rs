//! AES-128 round operations and the per-block encryption routine.

use std::array::from_fn;

use crate::shortint::server_key::LookupTable;
use crate::shortint::{Ciphertext, ServerKey};
use rayon::prelude::*;

use super::key::AesFheRoundKeys;
use super::sbox::sbox;

/// XOR `rhs` into `lhs` element-wise.
pub(super) fn xor_assign(sks: &ServerKey, lhs: &mut [Ciphertext], rhs: &[Ciphertext]) {
    for (s, k) in lhs.iter_mut().zip(rhs) {
        sks.unchecked_add_assign(s, k);
    }
}

/// AES ShiftRows: row `r` is rotated left by `r` bytes.
///
/// The state is 16 bytes in column-major order, byte `(row, col)` at index
/// `row + 4*col` (each byte spans 8 ciphertexts, so byte `b` is at bits
/// `8*b..8*b+8`):
///
/// ```text
///          col0 col1 col2 col3                col0 col1 col2 col3
///   row0 [  0    4    8   12 ]   --ShiftRows->   0    4    8   12   (<<< 0)
///   row1 [  1    5    9   13 ]                   5    9   13    1   (<<< 1)
///   row2 [  2    6   10   14 ]                  10   14    2    6   (<<< 2)
///   row3 [  3    7   11   15 ]                  15    3    7   11   (<<< 3)
/// ```
///
/// Each row's left-rotation is realized by the chain of byte swaps below
/// (rows 0 is a no-op; row 2's rotate-by-2 is two disjoint swaps).
pub(super) fn shift_rows(state: &mut [Ciphertext; 128]) {
    let (bytes, rest) = state.as_chunks_mut::<8>();
    debug_assert!(rest.is_empty());

    bytes.swap(1, 5);
    bytes.swap(5, 9);
    bytes.swap(9, 13);

    bytes.swap(2, 10);
    bytes.swap(6, 14);

    bytes.swap(15, 11);
    bytes.swap(11, 7);
    bytes.swap(7, 3);
}

/// Multiply a GF(2^8) byte by `x` (AES `xtime`), in LSB-first layout.
///
/// `bits[0..7]` shift to `result[1..8]` and `result[0] = bits[7]` (the MSB
/// becomes the new LSB, encoding the `+1` term of the reduction polynomial
/// `0x1B`). The three remaining bits of `0x1B` are at positions 1, 3, 4 in
/// LSB-first, so we XOR the old MSB into those positions and flush them
/// (positions 0, 2, 5, 6, 7 stay at noise 1 from the shift alone, but the
/// flushed three need to be ≤ 1 for the four-term MixColumns chain to fit
/// the `2_2` `max_noise_level = 5` budget).
fn xtime(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    bits: &[Ciphertext; 8],
) -> [Ciphertext; 8] {
    let msb = &bits[7];
    let mut result = [
        msb.clone(),
        bits[0].clone(),
        bits[1].clone(),
        bits[2].clone(),
        bits[3].clone(),
        bits[4].clone(),
        bits[5].clone(),
        bits[6].clone(),
    ];
    // The three flushes at positions 1, 3, 4 are independent, split disjoint
    // mut refs to run them in parallel.
    let [_, r1, _, r3, r4, _, _, _] = &mut result;
    [r1, r3, r4].par_iter_mut().for_each(|r| {
        sks.unchecked_add_assign(r, msb);
        sks.apply_lookup_table_assign(r, flush_lut);
    });
    result
}

/// AES MixColumns on a single 32-bit column. The four `xtime` calls are run
/// in parallel since they only depend on the input column.
pub(super) fn mix_columns_op(
    sks: &ServerKey,
    flush_lut: &LookupTable<Vec<u64>>,
    input: &[Ciphertext; 32],
) -> [Ciphertext; 32] {
    let (chunks, rest) = input.as_chunks::<8>();
    debug_assert!(rest.is_empty());
    let [c0, c1, c2, c3]: &[[Ciphertext; 8]; 4] = chunks.try_into().unwrap();

    let [mut b0, mut b1, mut b2, mut b3] = [c0, c1, c2, c3]
        .par_iter()
        .map(|c| xtime(sks, flush_lut, c))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let b0_copy = b0.clone();

    // Mix matrix [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2] applied row by row.
    xor_assign(sks, &mut b0, &b1);
    xor_assign(sks, &mut b0, c1);
    xor_assign(sks, &mut b0, c2);
    xor_assign(sks, &mut b0, c3);

    xor_assign(sks, &mut b1, c0);
    xor_assign(sks, &mut b1, &b2);
    xor_assign(sks, &mut b1, c2);
    xor_assign(sks, &mut b1, c3);

    xor_assign(sks, &mut b2, c0);
    xor_assign(sks, &mut b2, c1);
    xor_assign(sks, &mut b2, &b3);
    xor_assign(sks, &mut b2, c3);

    xor_assign(sks, &mut b3, c0);
    xor_assign(sks, &mut b3, c1);
    xor_assign(sks, &mut b3, c2);
    xor_assign(sks, &mut b3, &b0_copy);

    let mut iter = b0.into_iter().chain(b1).chain(b2).chain(b3);
    from_fn(|_| iter.next().unwrap())
}

fn mix_columns(sks: &ServerKey, flush_lut: &LookupTable<Vec<u64>>, state: &mut [Ciphertext]) {
    let (chunks, _) = state.as_chunks_mut::<32>();
    chunks
        .par_iter_mut()
        .for_each(|col: &mut [Ciphertext; 32]| {
            let mix_col = mix_columns_op(sks, flush_lut, col);
            col.clone_from_slice(&mix_col);
        });
}

fn sub_bytes(sks: &ServerKey, state: &mut [Ciphertext; 128], flush_lut: &LookupTable<Vec<u64>>) {
    state
        .par_chunks_mut(8)
        .for_each(|chunk| sbox(sks, flush_lut, chunk));
}

fn flush_state(sks: &ServerKey, state: &mut [Ciphertext], flush_lut: &LookupTable<Vec<u64>>) {
    state.par_iter_mut().for_each(|b| {
        sks.apply_lookup_table_assign(b, flush_lut);
    });
}

/// FHE AES-128 of a single public CTR counter block, returning its 128
/// keystream bits at noise level 1.
///
/// Noise contract: every `xor_assign` with a round key is followed by a
/// `flush_state`, so each pipeline stage (`sub_bytes`, `mix_columns`, the next
/// `xor_assign`) sees noise-1 inputs and never exceeds `max_noise_level`.
pub(super) fn encrypt_block(
    sks: &ServerKey,
    counter_value: u128,
    key: &AesFheRoundKeys,
) -> [Ciphertext; 128] {
    let bytes = counter_value.to_be_bytes();
    let mut state: [Ciphertext; 128] =
        from_fn(|i| sks.create_trivial(((bytes[i / 8] >> (i % 8)) & 1) as u64));
    let round_keys = key.round_keys();
    let flush_lut = key.flush_lut();

    xor_assign(sks, &mut state, &round_keys[0].key);
    for erk in &round_keys[1..10] {
        sub_bytes(sks, &mut state, flush_lut);
        flush_state(sks, &mut state, flush_lut);
        shift_rows(&mut state);
        mix_columns(sks, flush_lut, &mut state);
        flush_state(sks, &mut state, flush_lut);
        xor_assign(sks, &mut state, &erk.key);
        flush_state(sks, &mut state, flush_lut);
    }
    sub_bytes(sks, &mut state, flush_lut);
    shift_rows(&mut state);
    xor_assign(sks, &mut state, &round_keys[10].key);
    flush_state(sks, &mut state, flush_lut);

    state
}
