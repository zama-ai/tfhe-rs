mod comp;
mod no_patterns;
mod pattern;
mod trim;

pub use trim::split_ascii_whitespace;

use crate::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use crate::integer::prelude::*;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey as IntegerServerKey};
use crate::strings::ciphertext::{num_ascii_blocks, FheAsciiChar, FheString};
use crate::strings::N;
use rayon::prelude::*;
use std::borrow::Borrow;
use std::cmp::Ordering;

pub struct ServerKey<T>
where
    T: Borrow<IntegerServerKey> + Sync,
{
    inner: T,
}

pub type ServerKeyRef<'a> = ServerKey<&'a IntegerServerKey>;

impl<T> ServerKey<T>
where
    T: Borrow<IntegerServerKey> + Sync,
{
    pub fn inner(&self) -> &IntegerServerKey {
        self.inner.borrow()
    }

    pub fn new(inner: T) -> Self {
        Self { inner }
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
impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    pub(super) fn num_ascii_blocks(&self) -> usize {
        let sk = self.inner();

        assert_eq!(sk.message_modulus().0, sk.carry_modulus().0);

        num_ascii_blocks(sk.message_modulus())
    }

    pub fn trivial_encrypt_ascii(&self, str: &str, padding: Option<u32>) -> FheString {
        let sk = self.inner.borrow();

        super::ciphertext::trivial_encrypt_ascii(
            &sk.key,
            &crate::shortint::ServerKey::create_trivial,
            str,
            padding,
        )
    }

    // If an iterator is longer than the other, the "excess" characters are ignored. This function
    // performs the equality check by transforming the `str` and `pat` chars into two UInts
    fn asciis_eq<'a, I, U>(&self, str: I, pat: U) -> BooleanBlock
    where
        I: DoubleEndedIterator<Item = &'a FheAsciiChar>,
        U: DoubleEndedIterator<Item = &'a FheAsciiChar>,
    {
        let sk = self.inner();

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

        sk.eq_parallelized(&uint_str, &uint_pat)
    }

    fn clear_asciis_eq<'a, I>(&self, str: I, pat: &str) -> BooleanBlock
    where
        I: DoubleEndedIterator<Item = &'a FheAsciiChar>,
    {
        let sk = self.inner();

        let num_blocks = self.num_ascii_blocks();

        let blocks_str: Vec<_> = str
            .into_iter()
            .rev()
            .flat_map(|c| c.ciphertext().blocks().to_owned())
            .collect();
        let mut clear_pat = pat;

        let str_block_len = blocks_str.len();
        let pat_block_len = clear_pat.len() * num_blocks;

        let mut uint_str = RadixCiphertext::from_blocks(blocks_str);

        // Trim the str or pat such that the exceeding bytes are removed
        match str_block_len.cmp(&pat_block_len) {
            Ordering::Less => {
                // `str_block_len` is always a multiple of num_blocks as each char is num_blocks
                // blocks
                clear_pat = &clear_pat[..str_block_len / num_blocks];
            }
            Ordering::Greater => {
                let diff = str_block_len - pat_block_len;
                sk.trim_radix_blocks_lsb_assign(&mut uint_str, diff);
            }
            Ordering::Equal => (),
        }

        let clear_pat_uint = self.pad_cipher_and_cleartext_lsb(&mut uint_str, clear_pat);

        sk.scalar_eq_parallelized(&uint_str, clear_pat_uint)
    }

    fn asciis_eq_ignore_pat_pad<'a, I>(&self, str_pat: I) -> BooleanBlock
    where
        I: ParallelIterator<Item = (&'a FheAsciiChar, &'a FheAsciiChar)>,
    {
        let sk = self.inner();

        let mut result = sk.create_trivial_boolean_block(true);

        let eq_or_null_pat: Vec<_> = str_pat
            .map(|(str_char, pat_char)| {
                let (are_eq, pat_is_null) = rayon::join(
                    || sk.eq_parallelized(str_char.ciphertext(), pat_char.ciphertext()),
                    || sk.scalar_eq_parallelized(pat_char.ciphertext(), 0u8),
                );

                // If `pat_char` is null then `are_eq` is set to true. Hence if ALL `pat_char`s are
                // null, the result is always true, which is correct since the pattern is empty
                sk.boolean_bitor(&are_eq, &pat_is_null)
            })
            .collect();

        for eq_or_null in eq_or_null_pat {
            // Will be false if `str_char` != `pat_char` and `pat_char` isn't null
            sk.boolean_bitand_assign(&mut result, &eq_or_null);
        }

        result
    }

    fn pad_cipher_and_cleartext_lsb(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &str,
    ) -> StaticUnsignedBigInt<{ N * 8 / 64 }> {
        let sk = self.inner();

        let num_blocks = self.num_ascii_blocks();

        let mut rhs_bytes = rhs.as_bytes().to_vec();

        // Resize rhs with nulls at the end such that it matches the N const u8 length (for the
        // StaticUnsignedBigInt)
        rhs_bytes.resize(N, 0);

        let mut rhs_clear_uint = StaticUnsignedBigInt::<{ N * 8 / 64 }>::from(0u8);
        rhs_clear_uint.copy_from_be_byte_slice(&rhs_bytes);

        // Also fill the lhs with null blocks at the end
        if lhs.blocks().len() < N * num_blocks {
            let diff = N * num_blocks - lhs.blocks().len();
            sk.extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
        }

        rhs_clear_uint
    }

    fn pad_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let sk = self.inner();

        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                sk.extend_radix_with_trivial_zero_blocks_lsb_assign(lhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                sk.extend_radix_with_trivial_zero_blocks_lsb_assign(rhs, diff);
            }
            Ordering::Equal => (),
        }
    }

    fn pad_or_trim_ciphertext(&self, cipher: &mut RadixCiphertext, len: usize) {
        let sk = self.inner();

        let cipher_len = cipher.blocks().len();

        match cipher_len.cmp(&len) {
            Ordering::Less => {
                let diff = len - cipher_len;
                sk.extend_radix_with_trivial_zero_blocks_msb_assign(cipher, diff);
            }
            Ordering::Greater => {
                let diff = cipher_len - len;
                sk.trim_radix_blocks_msb_assign(cipher, diff);
            }
            Ordering::Equal => (),
        }
    }

    fn trim_ciphertexts_lsb(&self, lhs: &mut RadixCiphertext, rhs: &mut RadixCiphertext) {
        let sk = self.inner();

        let lhs_blocks = lhs.blocks().len();
        let rhs_blocks = rhs.blocks().len();

        match lhs_blocks.cmp(&rhs_blocks) {
            Ordering::Less => {
                let diff = rhs_blocks - lhs_blocks;
                sk.trim_radix_blocks_lsb_assign(rhs, diff);
            }
            Ordering::Greater => {
                let diff = lhs_blocks - rhs_blocks;
                sk.trim_radix_blocks_lsb_assign(lhs, diff);
            }
            Ordering::Equal => (),
        }
    }

    fn conditional_string(
        &self,
        condition: &BooleanBlock,
        true_ct: &FheString,
        false_ct: &FheString,
    ) -> FheString {
        let sk = self.inner();

        let mut true_ct = true_ct.clone();
        let mut false_ct = false_ct.clone();

        self.pad_strings(&mut true_ct, &mut false_ct);

        let true_is_padded = true_ct.is_padded();
        let false_is_padded = false_ct.is_padded();

        let true_ct_uint = true_ct.into_uint();
        let false_ct_uint = false_ct.into_uint();

        let result_uint = sk.if_then_else_parallelized(condition, &true_ct_uint, &false_ct_uint);

        let mut result = FheString::from_uint(result_uint, false);

        match (true_is_padded, false_is_padded) {
            (true, true) => {
                result.set_is_padded(true);
            }
            (true, false) | (false, true) => {
                // We don't know  if the result is padded or not.
                // We ensure that it is padded by adding a single null.
                result.append_null(self);
            }
            (false, false) => {}
        }

        result
    }

    fn pad_strings(&self, rhs: &mut FheString, lhs: &mut FheString) {
        loop {
            match rhs.len().cmp(&lhs.len()) {
                Ordering::Less => rhs.append_null(self),
                Ordering::Equal => break,
                Ordering::Greater => lhs.append_null(self),
            }
        }
    }

    fn left_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let sk = self.inner();

        let uint = str.to_uint();
        let mut shift_bits = sk.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let len = uint.blocks.len();

        let shifted = if len == 0 {
            uint
        } else {
            sk.left_shift_parallelized(&uint, &shift_bits)
        };

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.len() * 8) as u32;
        let shift_ge_than_str = sk.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = sk.if_then_else_parallelized(
            &shift_ge_than_str,
            &sk.create_trivial_zero_radix(len),
            &shifted,
        );

        FheString::from_uint(result, false)
    }

    fn right_shift_chars(&self, str: &FheString, shift: &RadixCiphertext) -> FheString {
        let sk = self.inner();

        let uint = str.to_uint();
        let mut shift_bits = sk.scalar_left_shift_parallelized(shift, 3);

        // `shift_bits` needs to have the same block len as `uint` for the tfhe-rs shift to work
        self.pad_or_trim_ciphertext(&mut shift_bits, uint.blocks().len());

        let len = uint.blocks().len();

        let shifted = if len == 0 {
            uint
        } else {
            sk.right_shift_parallelized(&uint, &shift_bits)
        };

        // If the shifting amount is >= than the str length we get zero i.e. all chars are out of
        // range (instead of wrapping, which is the behavior of Rust and tfhe-rs)
        let bit_len = (str.len() * 8) as u32;
        let shift_ge_than_str = sk.scalar_ge_parallelized(&shift_bits, bit_len);

        let result = sk.if_then_else_parallelized(
            &shift_ge_than_str,
            &sk.create_trivial_zero_radix(len),
            &shifted,
        );

        FheString::from_uint(result, false)
    }
}

pub trait FheStringIterator<T: Borrow<IntegerServerKey> + Sync> {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock);
}
