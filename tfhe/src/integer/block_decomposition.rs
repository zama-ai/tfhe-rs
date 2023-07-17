use core::ops::{AddAssign, BitAnd, ShlAssign, ShrAssign};
use std::ops::{BitOrAssign, Shl, Sub};

use crate::core_crypto::prelude::{CastFrom, CastInto, Numeric};
use crate::integer::{U256, U512};

// These work for signed number as rust uses 2-Complements
// And Arithmetic shift for signed number (logical for unsigned)
// https://doc.rust-lang.org/reference/expressions/operator-expr.html#arithmetic-and-logical-binary-operators

pub trait Decomposable:
    Numeric
    + BitAnd<Self, Output = Self>
    + ShrAssign<u32>
    + Eq
    + CastFrom<u32>
    + Shl<u32, Output = Self>
    + BitOrAssign<Self>
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
{
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
            impl Recomposable for $type { }
            impl RecomposableFrom<u64> for $type { }
            impl DecomposableInto<u64> for $type { }
            impl RecomposableFrom<u8> for $type { }
            impl DecomposableInto<u8> for $type { }
        )*
    };
}

impl_recomposable_decomposable!(u8, u16, u32, u64, u128, U256, U512, i8, i16, i32, i64, i128);

#[derive(Copy, Clone)]
pub struct BlockDecomposer<T> {
    data: T,
    bit_mask: T,
    num_bits_in_mask: u32,
    num_bits_valid: u32,
    padding_bit: T,
    limit: Option<T>,
}

impl<T> BlockDecomposer<T>
where
    T: Decomposable,
{
    pub fn with_early_stop_at_zero(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, Some(T::ZERO), T::ZERO)
    }

    pub fn with_padding_bit(value: T, bits_per_block: u32, padding_bit: T) -> Self {
        Self::new_(value, bits_per_block, None, padding_bit)
    }

    pub fn new(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, None, T::ZERO)
    }

    fn new_(value: T, bits_per_block: u32, limit: Option<T>, padding_bit: T) -> Self {
        assert!(bits_per_block <= T::BITS as u32);
        let num_bits_valid = T::BITS as u32;

        let num_bits_in_mask = bits_per_block;
        let bit_mask = 1_u32.checked_shl(bits_per_block).unwrap() - 1;
        let bit_mask = T::cast_from(bit_mask);

        Self {
            data: value,
            bit_mask,
            num_bits_in_mask,
            num_bits_valid,
            limit,
            padding_bit,
        }
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

        if self.limit.map(|limit| limit == self.data).unwrap_or(false) {
            return None;
        }

        let mut masked = self.data & self.bit_mask;
        self.data >>= self.num_bits_in_mask;

        if self.num_bits_valid < self.num_bits_in_mask {
            // This will be the case when self.num_bits_in_mask is not a multiple
            // of T::BITS.  We replace bits that
            // do not come from the actual T but from the padding
            // intoduced by the shift, to a specific value.
            for i in self.num_bits_valid..self.num_bits_in_mask {
                masked |= self.padding_bit << i;
            }
        }

        self.num_bits_valid = self.num_bits_valid.saturating_sub(self.num_bits_in_mask);

        Some(masked)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // In the case self we constructed with an early stop value
        // the upper bound might be higher than the actual number of iteration.
        //
        // The size_hint docs states that it is ok (not best thing
        // but won't break code)
        let max_remaining_iter = self.num_bits_valid / self.num_bits_in_mask;
        let min_remaining_iter = if max_remaining_iter != 0 { 1 } else { 0 };
        (min_remaining_iter, Some(max_remaining_iter as usize))
    }
}

impl<T> BlockDecomposer<T>
where
    T: Decomposable,
{
    pub fn iter_as<V>(self) -> impl Iterator<Item = V>
    where
        V: Numeric,
        T: CastInto<V>,
    {
        assert!(self.num_bits_in_mask <= V::BITS as u32);
        self.map(|masked| masked.cast_into())
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
    pub fn value(&self) -> T {
        if self.bit_pos >= T::BITS as u32 {
            self.data
        } else {
            let valid_mask = (T::ONE << self.bit_pos) - T::ONE;
            self.data & valid_mask
        }
    }

    pub fn unmasked_value(&self) -> T {
        self.data
    }
}

impl<T> BlockRecomposer<T>
where
    T: Recomposable,
{
    pub fn new(bits_per_block: u32) -> Self {
        let num_bits_in_block = bits_per_block;
        let bit_pos = 0;
        let bit_mask = 1_u32.checked_shl(bits_per_block).unwrap() - 1;
        let bit_mask = T::cast_from(bit_mask);

        Self {
            data: T::ZERO,
            bit_mask,
            num_bits_in_block,
            bit_pos,
        }
    }
}

impl<T> BlockRecomposer<T>
where
    T: Recomposable,
{
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
        self.data += block;
        self.bit_pos += self.num_bits_in_block;

        true
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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

    #[test]
    fn test_bit_block_decomposer_round_trip_unsigned() {
        for i in 0..u32::BITS {
            let value = (u16::MAX as u32).rotate_left(i);
            let bits_per_block = 2;
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

    #[test]
    fn test_bit_block_decomposer_round_trip_signed() {
        for i in 0..i32::BITS {
            let value = (i16::MAX as i32).rotate_left(i);
            let bits_per_block = 2;
            let blocks = BlockDecomposer::new(value, bits_per_block).collect::<Vec<_>>();

            let mut recomposer = BlockRecomposer::new(bits_per_block);
            for block in blocks {
                recomposer.add_unmasked(block);
            }
            let recomposed: i32 = recomposer.value();
            assert_eq!(recomposed, value);
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
}
