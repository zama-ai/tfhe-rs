use crate::core_crypto::prelude::{Numeric, UnsignedInteger};
use std::ops::{BitAnd, BitOrAssign, Not, Shl, ShlAssign, Shr, SubAssign};

const BYTES_PER_U64: usize = std::mem::size_of::<u64>() / std::mem::size_of::<u8>();

pub(crate) fn copy_from_le_byte_slice(lhs: &mut [u64], bytes: &[u8]) {
    assert_eq!(bytes.len(), lhs.len() * BYTES_PER_U64);

    let mut array = [0u8; BYTES_PER_U64];
    for (sub_bytes, word) in bytes.chunks_exact(BYTES_PER_U64).zip(lhs.iter_mut()) {
        array.copy_from_slice(sub_bytes);
        *word = u64::from_le_bytes(array);
    }
}

pub(crate) fn copy_from_be_byte_slice(lhs: &mut [u64], bytes: &[u8]) {
    assert_eq!(bytes.len(), lhs.len() * BYTES_PER_U64);

    let mut array = [0u8; BYTES_PER_U64];
    for (sub_bytes, word) in bytes.chunks_exact(BYTES_PER_U64).zip(lhs.iter_mut().rev()) {
        array.copy_from_slice(sub_bytes);
        *word = u64::from_be_bytes(array);
    }
}

pub(crate) fn copy_to_le_byte_slice(lhs: &[u64], bytes: &mut [u8]) {
    assert_eq!(bytes.len(), lhs.len() * BYTES_PER_U64);

    for (sub_bytes, word) in bytes.chunks_exact_mut(BYTES_PER_U64).zip(lhs.iter()) {
        sub_bytes.copy_from_slice(word.to_le_bytes().as_slice());
    }
}

pub(crate) fn copy_to_be_byte_slice(lhs: &[u64], bytes: &mut [u8]) {
    assert_eq!(bytes.len(), lhs.len() * BYTES_PER_U64);

    for (sub_bytes, word) in bytes.chunks_exact_mut(BYTES_PER_U64).zip(lhs.iter().rev()) {
        sub_bytes.copy_from_slice(word.to_be_bytes().as_slice());
    }
}

pub(crate) fn leading_zeros(lhs: &[u64]) -> u32 {
    // iter from msb to lsb
    for (i, word) in lhs.iter().copied().rev().enumerate() {
        let leading_zeros = word.leading_zeros();
        if leading_zeros != u64::BITS {
            return (i as u32 * u64::BITS) + leading_zeros;
        }
    }

    // Everyting is zero
    lhs.len() as u32 * u64::BITS
}

// Order of words must be little endian
pub(crate) fn compare<T>(lhs: T, rhs: T) -> std::cmp::Ordering
where
    T: AsRef<[u64]>,
{
    let lhs = lhs.as_ref();
    let rhs = rhs.as_ref();
    assert_eq!(lhs.len(), rhs.len());

    let lhs_iter = lhs.as_ref().iter().rev();
    let rhs_iter = rhs.as_ref().iter().rev();

    let mut current_ord = std::cmp::Ordering::Equal;
    for (w_self, w_other) in lhs_iter.zip(rhs_iter) {
        current_ord = w_self.cmp(w_other);
        if current_ord != std::cmp::Ordering::Equal {
            break;
        }
    }

    current_ord
}

pub(crate) fn bitnot_assign<T: Copy + Not<Output = T>>(words: &mut [T]) {
    for word in words {
        *word = !*word;
    }
}

pub(crate) fn bitand_assign(lhs: &mut [u64], rhs: &[u64]) {
    for (lhs_word, rhs_word) in lhs.iter_mut().zip(rhs.iter()) {
        *lhs_word &= rhs_word;
    }
}

pub(crate) fn bitor_assign(lhs: &mut [u64], rhs: &[u64]) {
    for (lhs_word, rhs_word) in lhs.iter_mut().zip(rhs.iter()) {
        *lhs_word |= rhs_word;
    }
}

pub(crate) fn bitxor_assign(lhs: &mut [u64], rhs: &[u64]) {
    for (lhs_word, rhs_word) in lhs.iter_mut().zip(rhs.iter()) {
        *lhs_word ^= rhs_word;
    }
}

#[inline(always)]
pub(crate) fn add_with_carry<T: UnsignedInteger>(l: T, r: T, c: bool) -> (T, bool) {
    let (lr, o0) = l.overflowing_add(r);
    let (lrc, o1) = lr.overflowing_add(T::cast_from(c));
    (lrc, o0 | o1)
}

pub(crate) fn add_assign_words<T: UnsignedInteger>(lhs: &mut [T], rhs: &[T]) {
    let iter = lhs
        .iter_mut()
        .zip(rhs.iter().copied().chain(std::iter::repeat(T::ZERO)));

    let mut carry = false;
    for (lhs_block, rhs_block) in iter {
        let (result, out_carry) = add_with_carry(*lhs_block, rhs_block, carry);
        *lhs_block = result;
        carry = out_carry;
    }
}

/// lhs and rhs are slice of words.
///
/// They must be in lsb -> msb order
pub(crate) fn schoolbook_mul_assign(lhs: &mut [u64], rhs: &[u64]) {
    assert!(lhs.len() >= rhs.len());
    let mut terms = Vec::with_capacity(rhs.len());

    for (i, rhs_block) in rhs.iter().copied().enumerate() {
        let mut blocks = Vec::with_capacity(lhs.len() + i);
        blocks.resize(i, 0u64); // pad with 0

        let mut carry = 0;
        for lhs_block in lhs.iter().copied() {
            let mut res = lhs_block as u128 * rhs_block as u128;
            res += carry;
            let carry_out = res >> u64::BITS;
            blocks.push((res & u64::MAX as u128) as u64);
            carry = carry_out;
        }
        blocks.push(carry as u64);

        terms.push(blocks)
    }

    let mut result = terms.pop().unwrap();
    for term in terms {
        add_assign_words(&mut result, &term);
    }

    for (lhs_block, result_block) in lhs.iter_mut().zip(result) {
        *lhs_block = result_block;
    }
}

pub(crate) fn slow_div<T>(numerator: T, divisor: T) -> (T, T)
where
    T: Numeric
        + ShlAssign<u32>
        + Shl<u32, Output = T>
        + Shr<u32, Output = T>
        + BitOrAssign<T>
        + SubAssign<T>
        + BitAnd<T, Output = T>
        + Ord,
{
    assert!(divisor != T::ZERO);

    let mut quotient = T::ZERO;
    let mut remainder = T::ZERO;

    for i in (0..T::BITS).rev() {
        remainder <<= 1;
        remainder |= (numerator >> i as u32) & T::ONE;

        if remainder >= divisor {
            remainder -= divisor;
            quotient |= T::ONE << (i as u32);
        }
    }

    (quotient, remainder)
}

// move bits from MSB to LSB
pub(crate) fn shr_assign(lhs: &mut [u64], shift: u32) {
    let len = lhs.len();
    let num_bits = len as u32 * u64::BITS;
    let shift = shift % num_bits;

    let num_rotations = (shift / u64::BITS) as usize;
    lhs.rotate_left(num_rotations);

    let len = lhs.len();
    let (head, tail) = lhs.split_at_mut(len - num_rotations);
    tail.fill(0);

    let shift_in_words = shift % u64::BITS;

    let value_mask = u64::MAX >> shift_in_words;
    let carry_mask = ((1u64 << shift_in_words) - 1u64).rotate_right(shift_in_words);

    let mut carry = 0u64;
    for word in &mut head.iter_mut().rev() {
        let rotated = word.rotate_right(shift_in_words);
        let value = (rotated & value_mask) | carry;
        let carry_for_next = rotated & carry_mask;

        *word = value;
        carry = carry_for_next;
    }
}

// move bits from LSB to MSB
pub(crate) fn shl_assign(lhs: &mut [u64], shift: u32) {
    let len = lhs.len();
    let num_bits = len as u32 * u64::BITS;
    let shift = shift % num_bits;

    let num_rotations = (shift / u64::BITS) as usize;
    lhs.rotate_right(num_rotations);

    let (head, tail) = lhs.split_at_mut(num_rotations);
    head.fill(0);

    let shift_in_words = shift % u64::BITS;

    let carry_mask = (1u64 << shift_in_words) - 1u64;
    let value_mask = u64::MAX << (shift_in_words);

    let mut carry = 0u64;
    for word in &mut tail.iter_mut() {
        let rotated = word.rotate_left(shift_in_words);
        let value = (rotated & value_mask) | carry;
        let carry_for_next = rotated & carry_mask;

        *word = value;
        carry = carry_for_next;
    }
}
