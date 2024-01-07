mod comp;
mod no_patterns;
mod pattern;
mod trim;

use crate::ciphertext::{FheAsciiChar, FheString};
use crate::client_key::ClientKey;
use crate::N;
use rayon::prelude::*;
use std::cmp::Ordering;
use tfhe::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use tfhe::integer::{BooleanBlock, IntegerCiphertext, RadixCiphertext, ServerKey as FheServerKey};

/// Represents a server key to operate homomorphically on [`FheString`].
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerKey {
    key: FheServerKey,
}

pub fn gen_keys() -> (ClientKey, ServerKey) {
    let ck = ClientKey::new();
    let sk = ServerKey::new(&ck);

    (ck, sk)
}

impl ServerKey {
    pub fn new(from: &ClientKey) -> Self {
        Self {
            key: FheServerKey::new_radix_server_key(from.key()),
        }
    }

    pub fn key(&self) -> &FheServerKey {
        &self.key
    }

    pub fn trivial_encrypt_ascii(&self, str: &str) -> TrivialEncryptOutput {
        assert!(str.is_ascii() & !str.contains('\0'));

        let enc_chars: Vec<_> = str
            .bytes()
            .map(|char| self.key.create_trivial_radix(char, 4))
            .collect();

        TrivialEncryptOutput { output: enc_chars }
    }
}

pub struct TrivialEncryptOutput {
    output: Vec<RadixCiphertext>,
}

impl TrivialEncryptOutput {
    pub fn value(self) -> Vec<RadixCiphertext> {
        self.output
    }
}

// With no padding, the length is just the vector's length (clear result). With padding it requires
// homomorphically counting the non zero elements (encrypted result).
pub enum FheStringLen {
    NoPadding(usize),
    Padding(RadixCiphertext),
}

pub enum FheStringIsEmpty {
    NoPadding(bool),
    Padding(BooleanBlock),
}

// A few helper functions for the implementations
impl ServerKey {
    // If an iterator is longer than the other, the "excess" characters are ignored. This function
    // performs the equality check by transforming the `str` and `pat` chars into two UInts
    fn asciis_eq<'a, I, U>(&self, str: I, pat: U) -> BooleanBlock
    where
        I: DoubleEndedIterator<Item = &'a FheAsciiChar>,
        U: DoubleEndedIterator<Item = &'a FheAsciiChar>,
    {
        let blocks_str = str
            .into_iter()
            .rev()
            .flat_map(|c| c.ciphertext().blocks().to_owned())
            .collect();

        let blocks_pat = pat
            .into_iter()
            .rev()
            .flat_map(|c| c.ciphertext().blocks().to_owned())
            .collect();

        let mut uint_str = RadixCiphertext::from_blocks(blocks_str);
        let mut uint_pat = RadixCiphertext::from_blocks(blocks_pat);

        self.trim_ciphertexts_lsb(&mut uint_str, &mut uint_pat);

        self.key.eq_parallelized(&uint_str, &uint_pat)
    }

    fn clear_asciis_eq<'a, I>(&self, str: I, pat: &str) -> BooleanBlock
    where
        I: DoubleEndedIterator<Item = &'a FheAsciiChar>,
    {
        let blocks_str: Vec<_> = str
            .into_iter()
            .rev()
            .flat_map(|c| c.ciphertext().blocks().to_owned())
            .collect();
        let mut clear_pat = pat;

        let str_block_len = blocks_str.len();
        let pat_block_len = clear_pat.len() * 4;

        let mut uint_str = RadixCiphertext::from_blocks(blocks_str);

        // Trim the str or pat such that the exceeding bytes are removed
        match str_block_len.cmp(&pat_block_len) {
            Ordering::Less => {
                // `str_block_len` is always a multiple of 4 as each char is 4 blocks
                clear_pat = &clear_pat[..str_block_len / 4];
            }
            Ordering::Greater => {
                let diff = str_block_len - pat_block_len;
                self.key.trim_radix_blocks_lsb_assign(&mut uint_str, diff);
            }
            _ => (),
        }

        let clear_pat_uint = self.pad_cipher_and_cleartext_lsb(&mut uint_str, clear_pat);

        self.key.scalar_eq_parallelized(&uint_str, clear_pat_uint)
    }

    fn asciis_eq_ignore_pat_pad<'a, I>(&self, str_pat: I) -> BooleanBlock
    where
        I: ParallelIterator<Item = (&'a FheAsciiChar, &'a FheAsciiChar)>,
    {
        let mut result = self.key.create_trivial_boolean_block(true);

        let eq_or_null_pat: Vec<_> = str_pat
            .map(|(str_char, pat_char)| {
                let (are_eq, pat_is_null) = rayon::join(
                    || {
                        self.key
                            .eq_parallelized(str_char.ciphertext(), pat_char.ciphertext())
                    },
                    || self.key.scalar_eq_parallelized(pat_char.ciphertext(), 0u8),
                );

                // If `pat_char` is null then `are_eq` is set to true. Hence if ALL `pat_char`s are
                // null, the result is always true, which is correct since the pattern is empty
                self.key.boolean_bitor(&are_eq, &pat_is_null)
            })
            .collect();

        for eq_or_null in eq_or_null_pat {
            // Will be false if `str_char` != `pat_char` and `pat_char` isn't null
            self.key.boolean_bitand_assign(&mut result, &eq_or_null);
        }

        result
    }

    fn pad_cipher_and_cleartext_lsb(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &str,
    ) -> StaticUnsignedBigInt<N> {
        let mut rhs_bytes = rhs.as_bytes().to_vec();

        // Resize rhs with nulls at the end such that it matches the N const u64 length (for the
        // StaticUnsignedBigInt)
        rhs_bytes.resize(N * 8, 0);

        let mut rhs_clear_uint = StaticUnsignedBigInt::<N>::from(0u8);
        rhs_clear_uint.copy_from_be_byte_slice(&rhs_bytes);

        // Also fill the lhs with null blocks at the end
        if lhs.blocks().len() < N * 8 * 4 {
            let diff = N * 8 * 4 - lhs.blocks().len();
            self.key
                .extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
        }

        rhs_clear_uint
    }

    fn pad_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                self.key
                    .extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                self.key
                    .extend_radix_with_trivial_zero_blocks_lsb_assign(rhs, diff);
            }
            _ => (),
        }
    }

    fn pad_or_trim_ciphertext(&self, cipher: &mut RadixCiphertext, len: usize) {
        let cipher_len = cipher.blocks().len();

        match cipher_len.cmp(&len) {
            Ordering::Less => {
                let diff = len - cipher_len;
                self.key
                    .extend_radix_with_trivial_zero_blocks_msb_assign(cipher, diff);
            }
            Ordering::Greater => {
                let diff = cipher_len - len;
                self.key.trim_radix_blocks_msb_assign(cipher, diff);
            }
            _ => (),
        }
    }

    fn trim_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                self.key.trim_radix_blocks_lsb_assign(rhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                self.key.trim_radix_blocks_lsb_assign(lhs, diff);
            }
            _ => (),
        }
    }

    fn conditional_string(
        &self,
        condition: &BooleanBlock,
        true_ct: FheString,
        false_ct: &FheString,
    ) -> FheString {
        let padded = true_ct.is_padded() && false_ct.is_padded();
        let potentially_padded = true_ct.is_padded() || false_ct.is_padded();

        let mut true_ct_uint = true_ct.into_uint(self);
        let mut false_ct_uint = false_ct.to_uint(self);

        self.pad_ciphertexts_lsb(&mut true_ct_uint, &mut false_ct_uint);

        let result_uint =
            self.key
                .if_then_else_parallelized(condition, &true_ct_uint, &false_ct_uint);

        let mut result = FheString::from_uint(result_uint);
        if padded {
            result.set_is_padded(true);
        } else if potentially_padded {
            // If the result is potentially padded we cannot assume it's not padded. We ensure that
            // result is padded with a single null that is ignored by our implementations
            result.append_null(self);
        }

        result
    }

    fn left_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted = self.key.left_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.chars().len() * 8) as u32;
        let shift_ge_than_str = self.key.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = self.key.if_then_else_parallelized(
            &shift_ge_than_str,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted,
        );

        FheString::from_uint(result)
    }

    fn right_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let uint = str.to_uint(self);
        let mut shift_bits = self.key.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let shifted = self.key.right_shift_parallelized(&uint, &shift_bits);

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.chars().len() * 8) as u32;
        let shift_ge_than_str = self.key.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = self.key.if_then_else_parallelized(
            &shift_ge_than_str,
            &self.key.create_trivial_zero_radix(uint.blocks().len()),
            &shifted,
        );

        FheString::from_uint(result)
    }
}

pub trait FheStringIterator {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock);
}

#[derive(Clone)]
enum CharIter<'a> {
    Iter(std::slice::Iter<'a, FheAsciiChar>),
    Extended(
        std::iter::Chain<std::slice::Iter<'a, FheAsciiChar>, std::iter::Once<&'a FheAsciiChar>>,
    ),
}

impl<'a> Iterator for CharIter<'a> {
    type Item = &'a FheAsciiChar;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            CharIter::Iter(iter) => iter.next(),
            CharIter::Extended(iter) => iter.next(),
        }
    }
}
