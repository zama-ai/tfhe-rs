use std::array::from_fn;

use crate::shortint::server_key::{BivariateLookupTableOwned, LookupTable};
use crate::shortint::{Ciphertext, ServerKey};
use rayon::prelude::*;

use super::sbox::sbox;

/// FHE-encrypted AES-128 round keys (11 round keys × 128 bits), plus the two
/// param-dependent LUTs (`x & 1` flush and bivariate AND) reused by every CTR
/// block. LUTs depend only on the [`ServerKey`] so we generate them once at
/// key construction.
pub struct AesFheKey {
    round_keys: [[Ciphertext; 128]; 11],
    flush_lut: LookupTable<Vec<u64>>,
    and_lut: BivariateLookupTableOwned,
}

impl AesFheKey {
    /// `key_bits` is the bit-encrypted 128-bit master key in the convention of
    /// [`super::data::encrypt_u128`] (NIST byte order, LSB-first within each
    /// byte).
    pub fn new(sks: &ServerKey, key_bits: &[Ciphertext; 128]) -> Self {
        let flush_lut = sks.generate_lookup_table(|x: u64| x & 1);
        let and_lut = sks.generate_lookup_table_bivariate(|a: u64, b: u64| a & b);
        let round_keys = key_expansion(sks, key_bits, &flush_lut, &and_lut);
        Self {
            round_keys,
            flush_lut,
            and_lut,
        }
    }

    pub(super) fn round_keys(&self) -> &[[Ciphertext; 128]; 11] {
        &self.round_keys
    }

    pub(super) fn flush_lut(&self) -> &LookupTable<Vec<u64>> {
        &self.flush_lut
    }

    pub(super) fn and_lut(&self) -> &BivariateLookupTableOwned {
        &self.and_lut
    }
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// NIST FIPS 197 §5.2 KeyExpansion (AES-128 only).
fn key_expansion(
    sks: &ServerKey,
    encrypted_key: &[Ciphertext; 128],
    flush_lut: &LookupTable<Vec<u64>>,
    and_lut: &BivariateLookupTableOwned,
) -> [[Ciphertext; 128]; 11] {
    const NK: usize = 4;
    const NR: usize = 10;
    const NB: usize = 4;
    const TOTAL_WORDS: usize = NB * (NR + 1);
    const WORD_BITS: usize = 32;
    const BYTE_BITS: usize = 8;

    let mut w = Vec::with_capacity(TOTAL_WORDS * WORD_BITS);
    w.extend(encrypted_key.iter().cloned());

    // `cks.encrypt(bit)` returns ciphertexts with `degree = message_modulus -
    // 1 = 3` (worst-case bound), which would propagate into `round_keys[0]`
    // and trip the bivariate AND `r.degree + 1 <= 4` assertion at the first
    // sbox call. Flushing brings the master key bits to degree 1, matching
    // the contract honored by the 40 derived words.
    w.par_iter_mut().for_each(|b| {
        sks.apply_lookup_table_assign(b, flush_lut);
    });

    // AES-256 would add an `else if Nk > 6 && i % Nk == 4 { temp = SubWord(temp) }`
    // branch (unreachable here with Nk = 4).
    for i in NK..TOTAL_WORDS {
        // NIST line 8: temp = w[i-1].
        let mut temp: Vec<Ciphertext> = w[(i - 1) * WORD_BITS..i * WORD_BITS].to_vec();

        // NIST line 10 (when applicable): temp = SubWord(RotWord(temp)) xor Rcon[i/Nk].
        // RotWord is folded into the read offset of the final XOR (below).
        let rot_shift = if i % NK == 0 {
            temp.par_chunks_mut(BYTE_BITS).for_each(|chunk| {
                sbox(sks, flush_lut, and_lut, chunk);
            });

            // Rcon is XOR'd into the byte that becomes byte 0 after RotWord.
            for bit in 0..BYTE_BITS {
                let rcon_bit = (RCON[i / NK - 1] >> bit) & 1;
                if rcon_bit == 1 {
                    sks.unchecked_scalar_add_assign(&mut temp[bit + BYTE_BITS], 1);
                }
            }

            BYTE_BITS
        } else {
            0
        };

        // NIST line 14: w[i] = w[i-Nk] xor temp.
        let w_minus_nk = &w[(i - NK) * WORD_BITS..(i - NK + 1) * WORD_BITS];
        let mut new_word: Vec<Ciphertext> = (0..WORD_BITS)
            .map(|bit| sks.unchecked_add(&w_minus_nk[bit], &temp[(bit + rot_shift) % WORD_BITS]))
            .collect();
        new_word.par_iter_mut().for_each(|b| {
            sks.apply_lookup_table_assign(b, flush_lut);
        });
        w.extend(new_word);
    }

    debug_assert_eq!(w.len(), (NR + 1) * (NB * WORD_BITS));
    let mut w_iter = w.into_iter();
    from_fn(|_| from_fn(|_| w_iter.next().unwrap()))
}
