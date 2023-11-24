use crate::core_crypto::prelude::{
    CastFrom, Numeric, SignedNumeric, UnsignedInteger, UnsignedNumeric,
};
use std::ops::{Add, BitAnd, BitOrAssign, Neg, Not, Shl, ShlAssign, Shr, Sub, SubAssign};

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

    // Everything is zero
    lhs.len() as u32 * u64::BITS
}

// Order of words must be little endian
pub(crate) fn compare_unsigned<T>(lhs: T, rhs: T) -> std::cmp::Ordering
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

// Order of words must be little endian
pub(crate) fn compare_signed<T>(lhs: T, rhs: T) -> std::cmp::Ordering
where
    T: AsRef<[u64]>,
{
    let lhs = lhs.as_ref();
    let rhs = rhs.as_ref();
    assert_eq!(lhs.len(), rhs.len());

    if lhs.is_empty() {
        // Both are empty
        return std::cmp::Ordering::Equal;
    }

    let most_significant_lhs = lhs.last().unwrap();
    let most_significant_rhs = rhs.last().unwrap();

    let lhs_sign_bit = most_significant_lhs >> (u64::BITS - 1);
    let rhs_sign_bit = most_significant_rhs >> (u64::BITS - 1);

    let cmp = most_significant_lhs.cmp(most_significant_rhs);
    if cmp == std::cmp::Ordering::Equal {
        return compare_unsigned(&lhs[..lhs.len() - 1], &rhs[..rhs.len() - 1]);
    }

    if lhs_sign_bit == rhs_sign_bit {
        cmp
    } else {
        // The block that has its sign bit set is going
        // to be ordered as 'greater' by the cmp fn.
        // However, we are dealing with signed number,
        // so in reality, it is the smaller of the two
        // i.e the cmp result is inversed
        match cmp {
            std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => unreachable!(),
        }
    }
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

        terms.push(blocks);
    }

    let mut result = terms.pop().unwrap();
    for term in terms {
        add_assign_words(&mut result, &term);
    }

    for (lhs_block, result_block) in lhs.iter_mut().zip(result) {
        *lhs_block = result_block;
    }
}

pub(crate) fn slow_div_unsigned<T>(numerator: T, divisor: T) -> (T, T)
where
    T: UnsignedNumeric
        + ShlAssign<u32>
        + Shl<u32, Output = T>
        + Shr<u32, Output = T>
        + BitOrAssign<T>
        + SubAssign<T>
        + BitAnd<T, Output = T>
        + Ord,
{
    assert_ne!(divisor, T::ZERO, "attempt to divide by 0");

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

pub(crate) fn slow_div_signed<T>(numerator: T, divisor: T) -> (T, T)
where
    T: SignedNumeric
        + ShlAssign<u32>
        + Shl<u32, Output = T>
        + Shr<u32, Output = T>
        + BitOrAssign<T>
        + SubAssign<T>
        + BitAnd<T, Output = T>
        + Ord
        + Neg<Output = T>
        + Add<T, Output = T>
        + Sub<T, Output = T>
        + CastFrom<T::NumericUnsignedType>,
    T::NumericUnsignedType: CastFrom<T>
        + ShlAssign<u32>
        + Shl<u32, Output = T::NumericUnsignedType>
        + Shr<u32, Output = T::NumericUnsignedType>
        + BitOrAssign<T::NumericUnsignedType>
        + SubAssign<T::NumericUnsignedType>
        + BitAnd<T::NumericUnsignedType, Output = T::NumericUnsignedType>
        + Ord
        + CastFrom<T>,
{
    assert!(divisor != T::ZERO);
    assert_eq!(
        T::BITS,
        T::NumericUnsignedType::BITS,
        "Signed and Unsigned types must have same number of bits"
    );

    let positive_numerator = if numerator < T::ZERO {
        -numerator
    } else {
        numerator
    };
    let positive_numerator = T::NumericUnsignedType::cast_from(positive_numerator);

    let positive_divisor =
        T::NumericUnsignedType::cast_from(if divisor < T::ZERO { -divisor } else { divisor });

    let (quotient, remainder) = slow_div_unsigned(positive_numerator, positive_divisor);

    let mut quotient = T::cast_from(quotient);
    let mut remainder = T::cast_from(remainder);

    let numerator_and_divisor_signs_differs = (divisor < T::ZERO) != (numerator < T::ZERO);

    if numerator < T::ZERO {
        remainder = -remainder;
    }

    if numerator_and_divisor_signs_differs {
        quotient = -quotient;
    }

    (quotient, remainder)
}

pub(crate) fn absolute_value<T>(value: T) -> T
where
    T: Numeric + Neg<Output = T>,
{
    if value < T::ZERO {
        -value
    } else {
        value
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ShiftType {
    Logical,
    Arithmetic,
}

// move bits from MSB to LSB
pub(crate) fn shr_assign(lhs: &mut [u64], shift: u32, shift_type: ShiftType) {
    let len = lhs.len();
    let num_bits = len as u32 * u64::BITS;
    let shift = shift % num_bits;

    let sign_bit = match shift_type {
        ShiftType::Logical => 0,
        ShiftType::Arithmetic => {
            // sign bit
            lhs.last().unwrap() >> (u64::BITS - 1)
        }
    };

    let num_rotations = (shift / u64::BITS) as usize;
    lhs.rotate_left(num_rotations);

    let len = lhs.len();
    let (head, tail) = lhs.split_at_mut(len - num_rotations);

    tail.fill(if sign_bit == 1 { u64::MAX } else { 0 });

    let shift_in_words = shift % u64::BITS;

    let value_mask = u64::MAX >> shift_in_words;
    let carry_mask = ((1u64 << shift_in_words) - 1u64).rotate_right(shift_in_words);

    let mut carry = if sign_bit == 1 {
        u64::MAX & carry_mask
    } else {
        0
    };
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
