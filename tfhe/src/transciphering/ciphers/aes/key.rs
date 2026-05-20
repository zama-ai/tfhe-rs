use std::array::from_fn;

use crate::shortint::server_key::LookupTable;
use crate::shortint::{Ciphertext, ServerKey};
use crate::transciphering::ciphers::aes::AesFheKey;
use rayon::prelude::*;

use super::sbox::sbox;

/// FHE-encrypted AES-128 round keys (11 round keys × 128 bits), plus the
/// param-dependent `x & 1` flush LUT reused by every CTR block. The LUT depends
/// only on the [`ServerKey`] so we generate it once at key construction.
pub struct AesFheRoundKeys {
    round_keys: [AesFheKey; 11],
    flush_lut: LookupTable<Vec<u64>>,
}

impl AesFheRoundKeys {
    /// `key_bits` is the bit-encrypted 128-bit master key in the convention of
    /// [`super::AesPlainKey::encrypt`] (NIST byte order, LSB-first within each
    /// byte, one clean degree-1 ciphertext per bit).
    ///
    /// # Panics
    ///
    /// AES transciphering is implemented for `MESSAGE_2_CARRY_2` parameters
    /// only: the whole noise budget (flushes target `noise ≤ 5`, accumulators
    /// reach degree 5 before a flush) assumes `message_modulus = carry_modulus
    /// = 4` and `max_noise_level ≥ 5`. This panics otherwise.
    pub fn new(sks: &ServerKey, key_bits: &AesFheKey) -> Self {
        assert_eq!(
            (sks.message_modulus.0, sks.carry_modulus.0),
            (4, 4),
            "AES transciphering is implemented for MESSAGE_2_CARRY_2 only \
             (got message_modulus={}, carry_modulus={})",
            sks.message_modulus.0,
            sks.carry_modulus.0,
        );
        assert!(
            sks.max_noise_level.get() >= 5,
            "AES transciphering needs max_noise_level >= 5, got {}",
            sks.max_noise_level.get(),
        );

        let flush_lut = sks.generate_lookup_table(|x: u64| x & 1);
        let round_keys = key_expansion(sks, key_bits, &flush_lut);
        Self {
            round_keys,
            flush_lut,
        }
    }

    pub(super) fn round_keys(&self) -> &[AesFheKey; 11] {
        &self.round_keys
    }

    pub(super) fn flush_lut(&self) -> &LookupTable<Vec<u64>> {
        &self.flush_lut
    }
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// NIST FIPS 197 §5.2 KeyExpansion (AES-128 only).
fn key_expansion(
    sks: &ServerKey,
    encrypted_key: &AesFheKey,
    flush_lut: &LookupTable<Vec<u64>>,
) -> [AesFheKey; 11] {
    const NK: usize = 4;
    const NR: usize = 10;
    const NB: usize = 4;
    const TOTAL_WORDS: usize = NB * (NR + 1);
    const WORD_BITS: usize = 32;
    const BYTE_BITS: usize = 8;

    let mut w = Vec::with_capacity(TOTAL_WORDS * WORD_BITS);
    w.extend(encrypted_key.key.iter().cloned());

    // AES-256 would add an `else if Nk > 6 && i % Nk == 4 { temp = SubWord(temp) }`
    // branch (unreachable here with Nk = 4).
    for i in NK..TOTAL_WORDS {
        // NIST line 8: temp = w[i-1].
        let mut temp: Vec<Ciphertext> = w[(i - 1) * WORD_BITS..i * WORD_BITS].to_vec();

        // NIST line 10 (when applicable): temp = SubWord(RotWord(temp)) xor Rcon[i/Nk].
        // RotWord is folded into the read offset of the final XOR (below).
        let rot_shift = if i % NK == 0 {
            temp.par_chunks_mut(BYTE_BITS).for_each(|chunk| {
                sbox(sks, flush_lut, chunk);
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
    from_fn(|_| AesFheKey::from(from_fn(|_| w_iter.next().unwrap())))
}
