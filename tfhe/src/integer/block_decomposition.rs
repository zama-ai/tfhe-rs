use crate::core_crypto::prelude::{CastFrom, CastInto, Numeric, SignedNumeric};
use crate::integer::bigint::static_signed::StaticSignedBigInt;
use crate::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use core::ops::{AddAssign, BitAnd, ShlAssign, ShrAssign};
use std::ops::{BitOrAssign, Not, Shl, Shr, Sub};

// These work for signed number as rust uses 2-Complements
// And Arithmetic shift for signed number (logical for unsigned)
// https://doc.rust-lang.org/reference/expressions/operator-expr.html#arithmetic-and-logical-binary-operators

pub trait Decomposable:
    Numeric
    + BitAnd<Self, Output = Self>
    + ShrAssign<u32>
    + Eq
    + CastFrom<u32>
    + Shr<u32, Output = Self>
    + Shl<u32, Output = Self>
    + BitOrAssign<Self>
    + Not<Output = Self>
{
}
pub trait Recomposable:
    Numeric
    + ShlAssign<u32>
    + AddAssign<Self>
    + CastFrom<u32>
    + BitAnd<Self, Output = Self>
    + Shl<u32, Output = Self>
    + Sub<Self, Output = Self>
    + Not<Output = Self>
{
    // TODO: need for wrapping arithmetic traits
    // This is a wrapping add but to avoid conflicts with other parts of the code using external
    // wrapping traits definition we change the name here
    #[must_use]
    fn recomposable_wrapping_add(self, other: Self) -> Self;
}

// Convenience traits have simpler bounds
pub trait RecomposableFrom<T>: Recomposable + CastFrom<T> {}
pub trait DecomposableInto<T>: Decomposable + CastInto<T> {}

macro_rules! impl_recomposable_decomposable {
    (
        $($type:ty),* $(,)?
    ) => {
        $(
            impl Decomposable for $type { }
            impl Recomposable for $type {
                #[inline]
                fn recomposable_wrapping_add(self, other: Self) -> Self {
                    self.wrapping_add(other)
                }
            }
            impl RecomposableFrom<u128> for $type { }
            impl DecomposableInto<u128> for $type { }
            impl RecomposableFrom<u64> for $type { }
            impl DecomposableInto<u64> for $type { }
            impl RecomposableFrom<u8> for $type { }
            impl DecomposableInto<u8> for $type { }
        )*
    };
}

impl_recomposable_decomposable!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128,);

impl<const N: usize> Decomposable for StaticSignedBigInt<N> {}
impl<const N: usize> Recomposable for StaticSignedBigInt<N> {
    #[inline]
    fn recomposable_wrapping_add(mut self, other: Self) -> Self {
        self.add_assign(other);
        self
    }
}
impl<const N: usize> RecomposableFrom<u128> for StaticSignedBigInt<N> {}
impl<const N: usize> RecomposableFrom<u64> for StaticSignedBigInt<N> {}
impl<const N: usize> RecomposableFrom<u8> for StaticSignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u128> for StaticSignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u64> for StaticSignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u8> for StaticSignedBigInt<N> {}

impl<const N: usize> Decomposable for StaticUnsignedBigInt<N> {}
impl<const N: usize> Recomposable for StaticUnsignedBigInt<N> {
    #[inline]
    fn recomposable_wrapping_add(mut self, other: Self) -> Self {
        self.add_assign(other);
        self
    }
}
impl<const N: usize> RecomposableFrom<u128> for StaticUnsignedBigInt<N> {}
impl<const N: usize> RecomposableFrom<u64> for StaticUnsignedBigInt<N> {}
impl<const N: usize> RecomposableFrom<u8> for StaticUnsignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u128> for StaticUnsignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u64> for StaticUnsignedBigInt<N> {}
impl<const N: usize> DecomposableInto<u8> for StaticUnsignedBigInt<N> {}

pub trait RecomposableSignedInteger:
    RecomposableFrom<u64>
    + std::ops::Neg<Output = Self>
    + std::ops::Shr<u32, Output = Self>
    + std::ops::BitOrAssign<Self>
    + std::ops::BitOr<Self, Output = Self>
    + std::ops::Mul<Self, Output = Self>
    + SignedNumeric
{
}

impl RecomposableSignedInteger for i8 {}
impl RecomposableSignedInteger for i16 {}
impl RecomposableSignedInteger for i32 {}
impl RecomposableSignedInteger for i64 {}
impl RecomposableSignedInteger for i128 {}

impl<const N: usize> RecomposableSignedInteger for StaticSignedBigInt<N> {}

pub trait SignExtendable:
    std::ops::Shl<u32, Output = Self> + std::ops::Shr<u32, Output = Self> + SignedNumeric
{
}

impl<T> SignExtendable for T where T: RecomposableSignedInteger {}

/// This function takes a signed integer of type `T` for which `num_bits_set`
/// have been set.
///
/// It will set the most significant bits to the value of the bit
/// at pos `num_bits_set - 1`.
///
/// This is used to correctly decrypt a signed radix ciphertext into a clear type
/// that has more bits than the original ciphertext.
///
/// This is like doing i8 as i16, i16 as i64, i16 as i8, etc
pub(in crate::integer) fn sign_extend_partial_number<T>(unpadded_value: T, num_bits_set: u32) -> T
where
    T: SignExtendable,
{
    if num_bits_set >= T::BITS as u32 {
        return unpadded_value;
    }

    // Shift to put the last set bit in the position of the sign bit of T
    // When right shifting this will do the sign extend automatically
    let shift = T::BITS as u32 - num_bits_set;
    (unpadded_value << shift) >> shift
}

/// Builds a mask having its `bits_per_block` low bits set, in the target type `T` itself.
///
/// # Panics
///
/// Panics if `bits_per_block` is 0, or greater than the number of bits of `T`.
fn low_bits_mask<T>(bits_per_block: u32) -> T
where
    T: Numeric + Not<Output = T> + Shl<u32, Output = T>,
{
    assert!(
        bits_per_block > 0 && bits_per_block <= T::BITS as u32,
        "bits_per_block must be in 1..=T::BITS"
    );

    if bits_per_block == T::BITS as u32 {
        // Shifting by the full width of a type would overflow
        !T::ZERO
    } else {
        // `(T::ONE << bits_per_block) - T::ONE` would overflow near the top of the range for signed
        // types
        !(!T::ZERO << bits_per_block)
    }
}

#[derive(Copy, Clone)]
#[repr(u32)]
pub enum PaddingBitValue {
    Zero = 0,
    One = 1,
}

#[derive(Clone)]
pub struct BlockDecomposer<T> {
    data: T,
    bit_mask: T,
    num_bits_in_mask: u32,
    num_bits_valid: u32,
    padding_bit: Option<PaddingBitValue>,
    limit: Option<T>,
}

impl<T> BlockDecomposer<T>
where
    T: Decomposable,
{
    /// Creates a block decomposer that will stop when the value reaches zero
    pub fn with_early_stop_at_zero(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, Some(T::ZERO), None)
    }

    /// Creates a block decomposer that will set the surplus bits to a specific value
    /// when bits_per_block is not a multiple of T::BITS
    pub fn with_padding_bit(value: T, bits_per_block: u32, padding_bit: PaddingBitValue) -> Self {
        Self::new_(value, bits_per_block, None, Some(padding_bit))
    }

    /// Creates a block decomposer that will return `block_count` blocks
    ///
    /// * If T is signed, extra block will be sign extended
    ///
    /// # Panics
    ///
    /// Panics if the total number of bits to decompose, i.e. `block_count * bits_per_block`, does
    /// not fit in a `u32`.
    pub fn with_block_count(value: T, bits_per_block: u32, block_count: usize) -> Self {
        let mut decomposer = Self::new(value, bits_per_block);
        let block_count: u32 = block_count.try_into().unwrap();
        // If the new number of bits is less than the actual number of bits, it means
        // data will be truncated
        //
        // If the new number of bits is greater than the actual number of bits, it means
        // the right shift used internally will correctly sign extend for us
        let num_bits_valid = block_count
            .checked_mul(bits_per_block)
            .expect("block_count * bits_per_block overflows a u32");
        decomposer.num_bits_valid = num_bits_valid;
        decomposer
    }

    pub fn new(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, None, None)
    }

    fn new_(
        value: T,
        bits_per_block: u32,
        limit: Option<T>,
        padding_bit: Option<PaddingBitValue>,
    ) -> Self {
        let num_bits_valid = T::BITS as u32;
        let num_bits_in_mask = bits_per_block;
        let bit_mask = low_bits_mask::<T>(bits_per_block);

        Self {
            data: value,
            bit_mask,
            num_bits_in_mask,
            num_bits_valid,
            limit,
            padding_bit,
        }
    }

    // We concretize the iterator type to allow usage of callbacks working on iterator for generic
    // integer encryption
    pub fn iter_as<V>(self) -> std::iter::Map<Self, fn(T) -> V>
    where
        V: Numeric,
        T: CastInto<V>,
    {
        assert!(self.num_bits_in_mask <= V::BITS as u32);
        self.map(CastInto::cast_into)
    }

    pub fn next_as<V>(&mut self) -> Option<V>
    where
        V: CastFrom<T>,
    {
        self.next().map(|masked| V::cast_from(masked))
    }

    pub fn checked_next_as<V>(&mut self) -> Option<V>
    where
        V: TryFrom<T>,
    {
        self.next().and_then(|masked| V::try_from(masked).ok())
    }
}

impl<T> Iterator for BlockDecomposer<T>
where
    T: Decomposable,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // This works by using the mask to get the bits we need
        // then shifting the source value to remove the bits
        // we just masked to be ready for the next iteration.
        if self.num_bits_valid == 0 {
            return None;
        }

        if self.limit.is_some_and(|limit| limit == self.data) {
            return None;
        }

        let mut masked = self.data & self.bit_mask;

        if self.num_bits_in_mask < T::BITS as u32 {
            self.data >>= self.num_bits_in_mask;
        } else {
            self.data = T::ZERO;
        }

        if self.num_bits_valid < self.num_bits_in_mask {
            // This will be the case when self.num_bits_in_mask is not a multiple
            // of T::BITS.
            //
            // We replace bits that do not come from the actual T but from the padding
            // introduced by the shift, to a specific value, if one was provided.
            if let Some(padding_bit) = self.padding_bit {
                let padding_mask = (self.bit_mask >> self.num_bits_valid) << self.num_bits_valid;
                masked = masked & !padding_mask;

                let padding_bit = T::cast_from(padding_bit as u32);
                for i in self.num_bits_valid..self.num_bits_in_mask {
                    masked |= padding_bit << i;
                }
            }
        }

        self.num_bits_valid = self.num_bits_valid.saturating_sub(self.num_bits_in_mask);

        Some(masked)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Mirror the conditions under which `next` stops returning blocks
        if self.num_bits_valid == 0 || self.limit.is_some_and(|limit| limit == self.data) {
            return (0, Some(0));
        }

        // `next` still produces a last, partial, block when fewer valid bits than the width of a
        // block remain, so the number of remaining blocks is a ceiling division. `num_bits_in_mask`
        // is never 0, the constructors reject that.
        let remaining_iter = self.num_bits_valid.div_ceil(self.num_bits_in_mask) as usize;

        if self.limit.is_some() {
            // The early stop value may be reached before all of the remaining blocks have been
            // produced, so only the upper bound is known
            (1, Some(remaining_iter))
        } else {
            (remaining_iter, Some(remaining_iter))
        }
    }
}

pub struct BlockRecomposer<T> {
    data: T,
    bit_mask: T,
    num_bits_in_block: u32,
    bit_pos: u32,
}

impl<T> BlockRecomposer<T>
where
    T: Recomposable,
{
    pub fn new(bits_per_block: u32) -> Self {
        let num_bits_in_block = bits_per_block;
        let bit_pos = 0;
        let bit_mask = low_bits_mask::<T>(bits_per_block);

        Self {
            data: T::ZERO,
            bit_mask,
            num_bits_in_block,
            bit_pos,
        }
    }

    pub fn value(&self) -> T {
        let is_signed = (T::ONE << (T::BITS as u32 - 1)) < T::ZERO;
        if self.bit_pos >= (T::BITS as u32 - u32::from(is_signed)) {
            self.data
        } else {
            let valid_mask = (T::ONE << self.bit_pos) - T::ONE;
            self.data & valid_mask
        }
    }

    pub fn unmasked_value(&self) -> T {
        self.data
    }

    pub fn add_unmasked<V>(&mut self, block: V) -> bool
    where
        T: CastFrom<V>,
    {
        let casted_block = T::cast_from(block);
        self.add(casted_block)
    }

    pub fn add_masked<V>(&mut self, block: V) -> bool
    where
        T: CastFrom<V>,
    {
        if self.bit_pos >= T::BITS as u32 {
            return false;
        }
        let casted_block = T::cast_from(block);
        self.add(casted_block & self.bit_mask)
    }

    fn add(&mut self, mut block: T) -> bool {
        if self.bit_pos >= T::BITS as u32 {
            return false;
        }

        block <<= self.bit_pos;
        self.data = self.data.recomposable_wrapping_add(block);
        self.bit_pos += self.num_bits_in_block;

        true
    }

    /// Recompose an unsigned integer, assumes all limbs from input contribute `bits_in_block` bits
    /// to the final result.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_unsigned<U>(input: impl Iterator<Item = U>, bits_in_block: u32) -> T
    where
        T: RecomposableFrom<U>,
    {
        let mut recomposer = Self::new(bits_in_block);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        recomposer.value()
    }

    /// Recompose an unsigned integer, all limbs from input are added as if contributing
    /// `bits_in_block` bits to the result, `unsigned_integer_size` indicates which of the low bits
    /// are actually considered as being part of the result, the bits beyond that are set to 0.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_unsigned_with_size<U>(
        input: impl Iterator<Item = U>,
        bits_in_block: u32,
        unsigned_integer_size: u32,
    ) -> T
    where
        T: RecomposableFrom<U>,
    {
        let mut recomposer = Self::new(bits_in_block);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        if T::BITS <= unsigned_integer_size as usize {
            recomposer.value()
        } else if unsigned_integer_size == 0 {
            T::ZERO
        } else {
            recomposer.value() & low_bits_mask::<T>(unsigned_integer_size)
        }
    }

    /// Recompose a signed integer, assumes all limbs from input contribute `bits_in_block` bits
    /// to the final result.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_signed<U>(input: impl Iterator<Item = U>, bits_in_block: u32) -> T
    where
        T: RecomposableFrom<U> + SignExtendable,
    {
        let mut recomposer = Self::new(bits_in_block);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        sign_extend_partial_number(recomposer.value(), recomposer.bit_pos)
    }

    /// Recompose a signed integer, all limbs from input are added as if contributing
    /// `bits_in_block` bits to the result, `signed_integer_size` indicates which of the low bits
    /// are actually considered as being part of the result, this is used to decide which bit
    /// represents the sign.
    ///
    /// For example with 2 limbs of 4 bits, if `signed_integer_size` is 6, then the 2 top bits from
    /// the last limb are ignored.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_signed_with_size<U>(
        input: impl Iterator<Item = U>,
        bits_in_block: u32,
        signed_integer_size: u32,
    ) -> T
    where
        T: RecomposableFrom<U> + SignExtendable,
    {
        let mut recomposer = Self::new(bits_in_block);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        sign_extend_partial_number(recomposer.value(), signed_integer_size)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::integer::U256;

    #[test]
    fn test_bit_block_decomposer() {
        let value = u16::MAX as u32;
        let bits_per_block = 2;
        let blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(expected_blocks, blocks);
    }

    #[test]
    fn test_bit_block_decomposer_3() {
        let bits_per_block = 3;

        let value = -1i8;
        let blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        // We expect the last block padded with 1s as a consequence of arithmetic shift
        let expected_blocks = vec![7, 7, 7];
        assert_eq!(expected_blocks, blocks);

        let value = i8::MIN;
        let blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        // We expect the last block padded with 1s as a consequence of arithmetic shift
        let expected_blocks = vec![0, 0, 6];
        assert_eq!(expected_blocks, blocks);

        let value = -1i8;
        let blocks =
            BlockDecomposer::with_padding_bit(value, bits_per_block, PaddingBitValue::Zero)
                .iter_as::<u64>()
                .collect::<Vec<_>>();
        // We expect the last block padded with 0s as we force that
        let expected_blocks = vec![7, 7, 3];
        assert_eq!(expected_blocks, blocks);
    }

    #[test]
    fn test_bit_block_decomposer_with_block_count() {
        let bits_per_block = 3;
        let expected_blocks = [0, 0, 6, 7, 7, 7, 7, 7, 7];
        let value = i8::MIN;
        for block_count in 1..expected_blocks.len() {
            let blocks = BlockDecomposer::with_block_count(value, bits_per_block, block_count)
                .iter_as::<u64>()
                .collect::<Vec<_>>();
            assert_eq!(expected_blocks[..block_count], blocks);
        }

        let bits_per_block = 3;
        let expected_blocks = [7, 7, 1, 0, 0, 0, 0, 0, 0];
        let value = i8::MAX;
        for block_count in 1..expected_blocks.len() {
            let blocks = BlockDecomposer::with_block_count(value, bits_per_block, block_count)
                .iter_as::<u64>()
                .collect::<Vec<_>>();
            assert_eq!(expected_blocks[..block_count], blocks);
        }

        let bits_per_block = 2;
        let expected_blocks = [0, 0, 0, 2, 3, 3, 3, 3, 3];
        let value = i8::MIN;
        for block_count in 1..expected_blocks.len() {
            let blocks = BlockDecomposer::with_block_count(value, bits_per_block, block_count)
                .iter_as::<u64>()
                .collect::<Vec<_>>();
            assert_eq!(expected_blocks[..block_count], blocks);
        }

        let bits_per_block = 2;
        let expected_blocks = [3, 3, 3, 1, 0, 0, 0, 0, 0, 0];
        let value = i8::MAX;
        for block_count in 1..expected_blocks.len() {
            let blocks = BlockDecomposer::with_block_count(value, bits_per_block, block_count)
                .iter_as::<u64>()
                .collect::<Vec<_>>();
            assert_eq!(expected_blocks[..block_count], blocks);
        }
    }

    #[test]
    fn test_bit_block_decomposer_recomposer_carry_handling_in_between() {
        let value = u16::MAX as u32;
        let bits_per_block = 2;
        let mut blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(expected_blocks, blocks);

        // Now this block, which is not the last will have a 'carry'
        blocks[0] += 2;

        let mut recomposer = BlockRecomposer::new(bits_per_block);
        for block in blocks {
            recomposer.add_unmasked(block);
        }
        let recomposed: u32 = recomposer.value();
        assert_eq!(recomposed, value.wrapping_add(2));
    }

    #[test]
    fn test_bit_block_decomposer_recomposer_carry_overflow() {
        let value = u16::MAX;
        let bits_per_block = 2;
        let mut blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3, 3, 3, 3, 3];
        assert_eq!(expected_blocks, blocks);

        // Now this block, which is not the last will have a 'carry'
        blocks[0] += 2;

        let mut recomposer = BlockRecomposer::new(bits_per_block);
        for block in blocks {
            recomposer.add_unmasked(block);
        }
        let recomposed: u16 = recomposer.value();
        assert_eq!(recomposed, value.wrapping_add(2));
    }

    #[test]
    fn test_bit_block_decomposer_recomposer_carry_bigger_recomposed_type() {
        // Test that when we use a bigger type to decompose / recompose our value
        // (by taking a smaller number of blocks), the recomposed value is
        // ok
        let value = u8::MAX as u16;
        let bits_per_block = 2;
        let mut blocks = BlockDecomposer::new(value, bits_per_block)
            .iter_as::<u64>()
            .take(4)
            .collect::<Vec<_>>();
        let expected_blocks = vec![3, 3, 3, 3];
        assert_eq!(expected_blocks, blocks);

        // Now this block, which is not the last will have a 'carry'
        blocks[0] += 2;

        let mut recomposer = BlockRecomposer::new(bits_per_block);
        for block in blocks {
            recomposer.add_unmasked(block);
        }
        let recomposed: u16 = recomposer.value();
        assert_eq!(recomposed, u8::MAX.wrapping_add(2) as u16);
    }

    /// Every block width the constructors accept must be usable, the mask used to be built in a
    /// `u32` which silently capped the usable width to 31 bits
    #[test]
    fn test_bit_block_decomposer_round_trip_unsigned() {
        for bits_per_block in 1..=u32::BITS {
            for i in 0..u32::BITS {
                let value = (u16::MAX as u32).rotate_left(i);
                let blocks = BlockDecomposer::new(value, bits_per_block)
                    .iter_as::<u64>()
                    .collect::<Vec<_>>();

                let mut recomposer = BlockRecomposer::new(bits_per_block);
                for block in blocks {
                    recomposer.add_unmasked(block);
                }
                let recomposed: u32 = recomposer.value();
                assert_eq!(recomposed, value, "bits_per_block: {bits_per_block}");
            }
        }
    }

    #[test]
    fn test_bit_block_decomposer_round_trip_signed() {
        for bits_per_block in 1..=i32::BITS {
            for i in 0..i32::BITS {
                let value = (i16::MAX as i32).rotate_left(i);
                let blocks = BlockDecomposer::new(value, bits_per_block).collect::<Vec<_>>();

                let mut recomposer = BlockRecomposer::new(bits_per_block);
                for block in blocks {
                    recomposer.add_unmasked(block);
                }
                let recomposed: i32 = recomposer.value();
                assert_eq!(recomposed, value, "bits_per_block: {bits_per_block}");
            }
        }
    }

    /// Test that when the bits per block is not a multiple of the number of bytes
    /// we can decompose and recompose
    #[test]
    fn test_bit_block_decomposer_round_trip_non_multiple_bits_per_block() {
        for i in 0..u32::BITS {
            let value = (u16::MAX as u32).rotate_left(i);
            let bits_per_block = 3;
            let blocks = BlockDecomposer::new(value, bits_per_block)
                .iter_as::<u64>()
                .collect::<Vec<_>>();

            let mut recomposer = BlockRecomposer::new(bits_per_block);
            for block in blocks {
                recomposer.add_unmasked(block);
            }
            let recomposed: u32 = recomposer.value();
            assert_eq!(recomposed, value);
        }
    }

    /// A block as wide as the decomposed type yields the whole value in a single block
    #[test]
    fn test_bit_block_decomposer_full_width_bits_per_block() {
        let value = u32::MAX;
        let blocks = BlockDecomposer::new(value, u32::BITS)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        let expected_blocks = vec![u32::MAX as u64];
        assert_eq!(expected_blocks, blocks);

        // For signed types the mask covers the sign bit as well
        let value = -1i8;
        let blocks = BlockDecomposer::new(value, i8::BITS).collect::<Vec<_>>();
        let expected_blocks = vec![-1i8];
        assert_eq!(expected_blocks, blocks);

        let value = i8::MIN;
        let blocks = BlockDecomposer::new(value, i8::BITS).collect::<Vec<_>>();
        let expected_blocks = vec![i8::MIN];
        assert_eq!(expected_blocks, blocks);
    }

    /// checks that `size_hint` does not understate its upper bound whenever a partial last
    /// block is still to be produced
    #[test]
    fn test_bit_block_decomposer_size_hint() {
        for bits_per_block in 1..=u64::BITS {
            let mut decomposer = BlockDecomposer::new(0x1234_5678_9abc_def0_u64, bits_per_block);
            let mut remaining = decomposer.clone().count();

            // Without an early stop value the number of remaining blocks is known exactly
            assert_eq!(
                decomposer.size_hint(),
                (remaining, Some(remaining)),
                "bits_per_block: {bits_per_block}"
            );

            while decomposer.next().is_some() {
                remaining -= 1;
                assert_eq!(
                    decomposer.size_hint(),
                    (remaining, Some(remaining)),
                    "bits_per_block: {bits_per_block}"
                );
            }
            assert_eq!(remaining, 0);
        }
    }

    /// checks `size_hint` correctly handle the early stop value
    #[test]
    fn test_bit_block_decomposer_size_hint_early_stop_at_zero() {
        // A value already equal to the early stop value produces no block at all
        let decomposer = BlockDecomposer::with_early_stop_at_zero(0_u64, 4);
        assert_eq!(decomposer.size_hint(), (0, Some(0)));
        assert_eq!(decomposer.count(), 0);

        // Otherwise the bounds must contain the number of blocks that are actually produced
        for value in [1_u64, 0xff, 0x1234_5678_9abc_def0] {
            let mut decomposer = BlockDecomposer::with_early_stop_at_zero(value, 4);
            loop {
                let (min, max) = decomposer.size_hint();
                let remaining = decomposer.clone().count();
                assert!(
                    min <= remaining,
                    "lower bound {min} > remaining {remaining}"
                );
                assert!(
                    max.is_none_or(|max| max >= remaining),
                    "upper bound {max:?} < remaining {remaining}"
                );
                if decomposer.next().is_none() {
                    break;
                }
            }
        }
    }

    /// Types wider than a `u32` are the ones the capped mask used to break on
    #[test]
    fn test_bit_block_decomposer_round_trip_every_bits_per_block_u256() {
        let value = U256::from((
            0x1234_5678_9abc_def0u64,
            0xfedc_ba98_7654_3210u64,
            0x0f0f_0f0f_0f0f_0f0fu64,
            0xa5a5_a5a5_a5a5_a5a5u64,
        ));
        for bits_per_block in 1..=U256::BITS {
            let blocks = BlockDecomposer::new(value, bits_per_block).collect::<Vec<_>>();

            let mut recomposer = BlockRecomposer::new(bits_per_block);
            for block in blocks {
                recomposer.add_unmasked(block);
            }
            let recomposed: U256 = recomposer.value();
            assert_eq!(recomposed, value, "bits_per_block: {bits_per_block}");
        }
    }

    /// A zero width block has no meaningful semantics: it used to make the decomposer iterate
    /// forever, panic in `size_hint`, and make the recomposer discard all of its input
    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=T::BITS")]
    fn test_bit_block_decomposer_zero_bits_per_block() {
        let _ = BlockDecomposer::new(u16::MAX as u32, 0);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=T::BITS")]
    fn test_bit_block_recomposer_zero_bits_per_block() {
        let _ = BlockRecomposer::<u32>::new(0);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=T::BITS")]
    fn test_bit_block_decomposer_too_many_bits_per_block() {
        let _ = BlockDecomposer::new(u16::MAX as u32, u32::BITS + 1);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=T::BITS")]
    fn test_bit_block_recomposer_too_many_bits_per_block() {
        let _ = BlockRecomposer::<u32>::new(u32::BITS + 1);
    }

    #[test]
    #[should_panic(expected = "block_count * bits_per_block overflows a u32")]
    fn test_bit_block_decomposer_with_block_count_overflow() {
        let _ = BlockDecomposer::with_block_count(u16::MAX as u32, 4, 1usize << 30);
    }

    /// The truncation mask used to be built as `(T::ONE << size) - T::ONE`, which overflows for a
    /// signed type when the size is one bit short of the type width
    #[test]
    fn test_bit_block_recomposer_with_size_signed() {
        let bits_per_block = 4;
        let blocks = [1u64, 2];
        // 1 in the first block, 2 in the second one
        let expected = 1i32 + (2i32 << bits_per_block);

        for size in [8u32, 16, 30, 31, 32] {
            let recomposed = BlockRecomposer::<i32>::recompose_unsigned_with_size(
                blocks.iter().copied(),
                bits_per_block,
                size,
            );
            assert_eq!(recomposed, expected, "unsigned_integer_size: {size}");
        }

        // A size of zero keeps none of the bits
        let recomposed = BlockRecomposer::<i32>::recompose_unsigned_with_size(
            blocks.iter().copied(),
            bits_per_block,
            0,
        );
        assert_eq!(recomposed, 0);
    }
}
