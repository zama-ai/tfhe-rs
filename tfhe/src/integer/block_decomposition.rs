use crate::core_crypto::prelude::{CastFrom, CastInto, DynamicNumeric, Numeric, SignedNumeric};
use crate::integer::bigint::static_signed::StaticSignedBigInt;
use crate::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use core::ops::{AddAssign, BitAnd, ShlAssign, ShrAssign};
use std::ops::{BitOrAssign, Not, Shl, Shr, Sub};

// These work for signed number as rust uses 2-Complements
// And Arithmetic shift for signed number (logical for unsigned)
// https://doc.rust-lang.org/reference/expressions/operator-expr.html#arithmetic-and-logical-binary-operators

/// Widest block the [`BlockDecomposer`] can produce and the [`BlockRecomposer`] can consume
pub const MAX_BITS_PER_BLOCK: u32 = u128::BITS;

/// Trait giving bit-level view of a clear integer, needed to split it into blocks.
///
/// Signed types are seen as two's complement:
/// * [`Self::low_bits`] returns the low bits of the two's complement pattern
/// * [`Self::shift_right`] is arithmetic.
pub trait Decomposable: DynamicNumeric {
    /// Returns the `n` lowest bits of the two's complement bit pattern, `n` in `1..=128`.
    ///
    /// Bits beyond [`DynamicNumeric::bit_width`] are the sign extension for signed types and
    /// zero for unsigned ones.
    fn low_bits(&self, n: u32) -> u128;

    /// Shifts right by `n` bits, arithmetic for signed types, logical otherwise.
    ///
    /// Unlike `>>=`, `n >= self.bit_width()` is allowed and results in zero, or all ones for a
    /// negative value.
    fn shift_right(&mut self, n: u32);
}

/// Bit-level view of a clear integer, as needed to build it back from blocks.
///
/// Arithmetic is wrapping at [`DynamicNumeric::bit_width`] bits.
pub trait Recomposable: DynamicNumeric {
    /// `self = self.wrapping_add(limb << bit_pos)`, with `bit_pos < self.bit_width()`
    fn wrapping_add_shifted(&mut self, limb: u128, bit_pos: u32);

    /// Clears all the bits but the `n` lowest ones, with `n < self.bit_width()`
    fn keep_low_bits(&mut self, n: u32);
}

/// Signed clear integer that can be sign extended from an arbitrary bit position
pub trait SignExtendable: Recomposable {
    /// Sets the bits at position `n` and above to the value of the bit at position `n - 1`.
    ///
    /// This is like doing `i8 as i16`, `i16 as i64`, `i16 as i8`, etc.  
    ///
    /// `n >= self.bit_width()`, (i.e extending from a 'wider' width)
    /// means there is nothing to extend from,  leave the value untouched.
    ///
    /// `n == 0` clears it.
    fn sign_extend_from(&mut self, n: u32);
}

/// Clear operand of an operation, split into blocks of type `T`.
pub trait DecomposableInto<T>: Decomposable + CastInto<T> {}
impl<T, V> DecomposableInto<V> for T where T: Decomposable + CastInto<V> {}

/// Clear value built from blocks of type `T`, e.g. by decryption.
pub trait RecomposableFrom<T>: Recomposable + CastFrom<T> {}
impl<T, V> RecomposableFrom<V> for T where T: Recomposable + CastFrom<V> {}

/// Transitional bound of the operations that still rely on a clear operand having a fixed width
/// known at compile time (`T::BITS`, `T::ZERO`, shifts by a `u32`, ...).
///
/// These are the bounds [`Decomposable`] used to have. An operation bounded by this trait cannot
/// accept dynamically sized clear integers yet.
pub trait FixedDecomposableInto<T>:
    DecomposableInto<T>
    + Numeric
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

impl<T, V> FixedDecomposableInto<V> for T where
    T: DecomposableInto<V>
        + Numeric
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

/// Transitional bound of the operations that still rely on a clear result having a fixed width
/// known at compile time, same story as [`FixedDecomposableInto`].
pub trait FixedRecomposableFrom<T>:
    RecomposableFrom<T>
    + Numeric
    + ShlAssign<u32>
    + AddAssign<Self>
    + CastFrom<u32>
    + BitAnd<Self, Output = Self>
    + Shl<u32, Output = Self>
    + Sub<Self, Output = Self>
    + Not<Output = Self>
{
}

impl<T, V> FixedRecomposableFrom<V> for T where
    T: RecomposableFrom<V>
        + Numeric
        + ShlAssign<u32>
        + AddAssign<Self>
        + CastFrom<u32>
        + BitAnd<Self, Output = Self>
        + Shl<u32, Output = Self>
        + Sub<Self, Output = Self>
        + Not<Output = Self>
{
}

/// Mask having its `n` low bits set, `n` in `0..=128`
fn low_bits_mask(n: u32) -> u128 {
    if n >= u128::BITS {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

fn assert_bits_per_block(bits_per_block: u32) {
    assert!(
        bits_per_block > 0 && bits_per_block <= MAX_BITS_PER_BLOCK,
        "bits_per_block must be in 1..={MAX_BITS_PER_BLOCK}"
    );
}

/// Implements [`Decomposable`] and [`Recomposable`] for a fixed width type that implements
/// [`Numeric`] (and so [`DynamicNumeric`] through the blanket impl), the wrapping addition of two
/// values is given as an expression as the primitive types and the static big integers spell it
/// differently.
macro_rules! impl_fixed_width {
    ([$($gen:tt)*] $t:ty, ($a:ident, $b:ident) => $wrapping_add:expr) => {
        impl<$($gen)*> Decomposable for $t {
            #[inline]
            fn low_bits(&self, n: u32) -> u128 {
                // Casting a signed value to u128 sign extends, which is the two's complement
                // pattern we want
                let pattern: u128 = (*self).cast_into();
                pattern & low_bits_mask(n)
            }

            #[inline]
            fn shift_right(&mut self, n: u32) {
                if n >= <$t as Numeric>::BITS as u32 {
                    *self = if *self < <$t as Numeric>::ZERO {
                        !<$t as Numeric>::ZERO
                    } else {
                        <$t as Numeric>::ZERO
                    };
                } else {
                    *self >>= n;
                }
            }
        }

        impl<$($gen)*> Recomposable for $t {
            #[inline]
            fn wrapping_add_shifted(&mut self, limb: u128, bit_pos: u32) {
                let $a = *self;
                let $b = <$t as CastFrom<u128>>::cast_from(limb) << bit_pos;
                *self = $wrapping_add;
            }

            #[inline]
            fn keep_low_bits(&mut self, n: u32) {
                // `(T::ONE << n) - T::ONE` would overflow near the top of the range for signed
                // types
                *self &= !(!<$t as Numeric>::ZERO << n);
            }
        }
    };
}

macro_rules! impl_fixed_width_primitives {
    ($($t:ty),* $(,)?) => {
        $(
            impl_fixed_width!([] $t, (a, b) => a.wrapping_add(b));
        )*
    };
}

impl_fixed_width_primitives!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

// The additions of the static big integers are wrapping
impl_fixed_width!([const N: usize] StaticUnsignedBigInt<N>, (a, b) => {
    let mut sum = a;
    sum += b;
    sum
});
impl_fixed_width!([const N: usize] StaticSignedBigInt<N>, (a, b) => {
    let mut sum = a;
    sum += b;
    sum
});

macro_rules! impl_sign_extendable {
    ([$($gen:tt)*] $t:ty) => {
        impl<$($gen)*> SignExtendable for $t {
            fn sign_extend_from(&mut self, n: u32) {
                let bits = <$t as Numeric>::BITS as u32;
                if n == 0 {
                    *self = <$t as Numeric>::ZERO;
                } else if n < bits {
                    // Shift to put the last set bit in the position of the sign bit
                    // When right shifting this will do the sign extend automatically
                    let shift = bits - n;
                    *self = (*self << shift) >> shift;
                }
            }
        }
    };
}

impl_sign_extendable!([] i8);
impl_sign_extendable!([] i16);
impl_sign_extendable!([] i32);
impl_sign_extendable!([] i64);
impl_sign_extendable!([] i128);
impl_sign_extendable!([const N: usize] StaticSignedBigInt<N>);

pub trait RecomposableSignedInteger:
    FixedRecomposableFrom<u64>
    + SignExtendable
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

#[derive(Copy, Clone)]
#[repr(u32)]
pub enum PaddingBitValue {
    Zero = 0,
    One = 1,
}

/// Iterator over the blocks of a clear value, least significant block first.
///
/// Blocks are at most [`MAX_BITS_PER_BLOCK`] wide and are yielded as `u128`, see
/// [`Self::iter_as`] to get them as a smaller type.
#[derive(Clone)]
pub struct BlockDecomposer<T> {
    data: T,
    bit_mask: u128,
    num_bits_in_mask: u32,
    num_bits_valid: u32,
    padding_bit: Option<PaddingBitValue>,
    stop_at_zero: bool,
}

impl<T> BlockDecomposer<T>
where
    T: Decomposable,
{
    /// Creates a block decomposer that will stop when the value reaches zero
    pub fn with_early_stop_at_zero(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, true, None)
    }

    /// Creates a block decomposer that will set the surplus bits to a specific value
    /// when bits_per_block is not a multiple of the width of the value
    pub fn with_padding_bit(value: T, bits_per_block: u32, padding_bit: PaddingBitValue) -> Self {
        Self::new_(value, bits_per_block, false, Some(padding_bit))
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

    /// Creates a block decomposer that will return as many blocks as needed to cover
    /// all the bits of the value
    ///
    /// # Panics
    ///
    /// Panics if `bits_per_block` is 0, or greater than [`MAX_BITS_PER_BLOCK`].
    pub fn new(value: T, bits_per_block: u32) -> Self {
        Self::new_(value, bits_per_block, false, None)
    }

    fn new_(
        value: T,
        bits_per_block: u32,
        stop_at_zero: bool,
        padding_bit: Option<PaddingBitValue>,
    ) -> Self {
        assert_bits_per_block(bits_per_block);

        Self {
            num_bits_valid: value.bit_width(),
            data: value,
            bit_mask: low_bits_mask(bits_per_block),
            num_bits_in_mask: bits_per_block,
            padding_bit,
            stop_at_zero,
        }
    }

    // We concretize the iterator type to allow usage of callbacks working on iterator for generic
    // integer encryption
    pub fn iter_as<V>(self) -> std::iter::Map<Self, fn(u128) -> V>
    where
        V: Numeric + CastFrom<u128>,
    {
        assert!(self.num_bits_in_mask <= V::BITS as u32);
        self.map(V::cast_from)
    }

    pub fn next_as<V>(&mut self) -> Option<V>
    where
        V: CastFrom<u128>,
    {
        self.next().map(V::cast_from)
    }

    pub fn checked_next_as<V>(&mut self) -> Option<V>
    where
        V: TryFrom<u128>,
    {
        self.next().and_then(|block| V::try_from(block).ok())
    }
}

impl<T> Iterator for BlockDecomposer<T>
where
    T: Decomposable,
{
    type Item = u128;

    fn next(&mut self) -> Option<Self::Item> {
        // This works by extracting the bits we need
        // then shifting the source value to remove the bits
        // we just extracted to be ready for the next iteration.
        if self.num_bits_valid == 0 {
            return None;
        }

        if self.stop_at_zero && self.data.is_zero() {
            return None;
        }

        let mut block = self.data.low_bits(self.num_bits_in_mask);
        self.data.shift_right(self.num_bits_in_mask);

        if self.num_bits_valid < self.num_bits_in_mask {
            // This will be the case when self.num_bits_in_mask is not a multiple
            // of the width of the value.
            //
            // We replace bits that do not come from the actual value but from the padding
            // introduced by the shift, to a specific value, if one was provided.
            if let Some(padding_bit) = self.padding_bit {
                let padding_mask = (self.bit_mask >> self.num_bits_valid) << self.num_bits_valid;
                block = match padding_bit {
                    PaddingBitValue::Zero => block & !padding_mask,
                    PaddingBitValue::One => block | padding_mask,
                };
            }
        }

        self.num_bits_valid = self.num_bits_valid.saturating_sub(self.num_bits_in_mask);

        Some(block)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Mirror the conditions under which `next` stops returning blocks
        if self.num_bits_valid == 0 || (self.stop_at_zero && self.data.is_zero()) {
            return (0, Some(0));
        }

        // `next` still produces a last, partial, block when fewer valid bits than the width of a
        // block remain, so the number of remaining blocks is a ceiling division. `num_bits_in_mask`
        // is never 0, the constructors reject that.
        let remaining_iter = self.num_bits_valid.div_ceil(self.num_bits_in_mask) as usize;

        if self.stop_at_zero {
            // The early stop value may be reached before all of the remaining blocks have been
            // produced, so only the upper bound is known
            (1, Some(remaining_iter))
        } else {
            (remaining_iter, Some(remaining_iter))
        }
    }
}

/// Builds a clear value from its blocks, least significant block first.
pub struct BlockRecomposer<T> {
    data: T,
    bit_mask: u128,
    num_bits_in_block: u32,
    bit_pos: u32,
}

impl<T> BlockRecomposer<T>
where
    T: Recomposable,
{
    /// Creates a recomposer for a value of `bit_width` bits, fixed width types ignore it.
    ///
    /// # Panics
    ///
    /// Panics if `bits_per_block` is 0, or greater than [`MAX_BITS_PER_BLOCK`].
    pub fn new(bits_per_block: u32, bit_width: u32) -> Self {
        assert_bits_per_block(bits_per_block);

        Self {
            data: T::zero_with_width(bit_width),
            bit_mask: low_bits_mask(bits_per_block),
            num_bits_in_block: bits_per_block,
            bit_pos: 0,
        }
    }

    /// The recomposed value, without the bits that come from the carries of the last added block
    pub fn value(&self) -> T {
        let mut value = self.data.clone();
        if self.bit_pos < value.bit_width() {
            value.keep_low_bits(self.bit_pos);
        }
        value
    }

    pub fn unmasked_value(&self) -> T {
        self.data.clone()
    }

    pub fn add_unmasked<V>(&mut self, block: V) -> bool
    where
        V: CastInto<u128>,
    {
        self.add(block.cast_into())
    }

    pub fn add_masked<V>(&mut self, block: V) -> bool
    where
        V: CastInto<u128>,
    {
        self.add(block.cast_into() & self.bit_mask)
    }

    fn add(&mut self, block: u128) -> bool {
        if self.bit_pos >= self.data.bit_width() {
            return false;
        }

        self.data.wrapping_add_shifted(block, self.bit_pos);
        self.bit_pos += self.num_bits_in_block;

        true
    }

    /// Recompose an unsigned integer of `bit_width` bits, assumes all limbs from input contribute
    /// `bits_in_block` bits to the final result.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_unsigned<U>(
        input: impl Iterator<Item = U>,
        bits_in_block: u32,
        bit_width: u32,
    ) -> T
    where
        U: CastInto<u128>,
    {
        let mut recomposer = Self::new(bits_in_block, bit_width);
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
        U: CastInto<u128>,
    {
        let mut recomposer = Self::new(bits_in_block, unsigned_integer_size);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        let mut value = recomposer.value();
        if unsigned_integer_size < value.bit_width() {
            value.keep_low_bits(unsigned_integer_size);
        }
        value
    }

    /// Recompose a signed integer of `bit_width` bits, assumes all limbs from input contribute
    /// `bits_in_block` bits to the final result.
    ///
    /// Input is expected in little endian order.
    pub fn recompose_signed<U>(
        input: impl Iterator<Item = U>,
        bits_in_block: u32,
        bit_width: u32,
    ) -> T
    where
        T: SignExtendable,
        U: CastInto<u128>,
    {
        let mut recomposer = Self::new(bits_in_block, bit_width);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        let mut value = recomposer.value();
        value.sign_extend_from(recomposer.bit_pos);
        value
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
        T: SignExtendable,
        U: CastInto<u128>,
    {
        let mut recomposer = Self::new(bits_in_block, signed_integer_size);
        for limb in input {
            if !recomposer.add_unmasked(limb) {
                break;
            }
        }

        let mut value = recomposer.value();
        value.sign_extend_from(signed_integer_size);
        value
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::integer::{I256, U256};

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

        let value = 1u8;
        let blocks = BlockDecomposer::with_padding_bit(value, bits_per_block, PaddingBitValue::One)
            .iter_as::<u64>()
            .collect::<Vec<_>>();
        // 8 bits is 3 + 3 + 2, the last block has one padding bit, which we force to 1
        let expected_blocks = vec![1, 0, 4];
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

    /// Extra blocks are sign extended even when a block is as wide as, or wider than, the value
    #[test]
    fn test_bit_block_decomposer_with_block_count_wide_blocks() {
        let blocks = BlockDecomposer::with_block_count(i8::MIN, i8::BITS, 3).collect::<Vec<_>>();
        assert_eq!(blocks, vec![0b1000_0000, 0b1111_1111, 0b1111_1111]);

        let blocks = BlockDecomposer::with_block_count(i8::MAX, i8::BITS, 3).collect::<Vec<_>>();
        assert_eq!(blocks, vec![0b0111_1111, 0, 0]);

        let blocks = BlockDecomposer::with_block_count(-1i8, 16, 2).collect::<Vec<_>>();
        assert_eq!(blocks, vec![0b1111_1111_1111_1111, 0b1111_1111_1111_1111]);

        let blocks = BlockDecomposer::with_block_count(u8::MAX, 16, 2).collect::<Vec<_>>();
        assert_eq!(blocks, vec![0b1111_1111, 0]);
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

        let mut recomposer = BlockRecomposer::new(bits_per_block, u32::BITS);
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

        let mut recomposer = BlockRecomposer::new(bits_per_block, u16::BITS);
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

        let mut recomposer = BlockRecomposer::new(bits_per_block, u16::BITS);
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

                let mut recomposer = BlockRecomposer::new(bits_per_block, u32::BITS);
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

                let mut recomposer = BlockRecomposer::new(bits_per_block, i32::BITS);
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

            let mut recomposer = BlockRecomposer::new(bits_per_block, u32::BITS);
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

        // For signed types the block covers the sign bit as well
        let value = -1i8;
        let blocks = BlockDecomposer::new(value, i8::BITS).collect::<Vec<_>>();
        let expected_blocks = vec![0b1111_1111];
        assert_eq!(expected_blocks, blocks);

        let value = i8::MIN;
        let blocks = BlockDecomposer::new(value, i8::BITS).collect::<Vec<_>>();
        let expected_blocks = vec![0b1000_0000];
        assert_eq!(expected_blocks, blocks);

        // A block wider than the value is sign extended
        let value = -1i8;
        let blocks = BlockDecomposer::new(value, 16).collect::<Vec<_>>();
        let expected_blocks = vec![0b1111_1111_1111_1111];
        assert_eq!(expected_blocks, blocks);

        let value = u8::MAX;
        let blocks = BlockDecomposer::new(value, 16).collect::<Vec<_>>();
        let expected_blocks = vec![0b1111_1111];
        assert_eq!(expected_blocks, blocks);
    }

    /// The widest block that can be produced and consumed
    #[test]
    fn test_bit_block_decomposer_round_trip_max_bits_per_block() {
        let value = 0x1234_5678_9abc_def0_fedc_ba98_7654_3210u128;
        let blocks = BlockDecomposer::new(value, MAX_BITS_PER_BLOCK).collect::<Vec<_>>();
        assert_eq!(blocks, vec![value]);

        let recomposed: u128 =
            BlockRecomposer::recompose_unsigned(blocks.into_iter(), MAX_BITS_PER_BLOCK, u128::BITS);
        assert_eq!(recomposed, value);

        let value = -0x1234_5678_9abc_def0_fedc_ba98_7654_3210i128;
        let blocks = BlockDecomposer::new(value, MAX_BITS_PER_BLOCK).collect::<Vec<_>>();
        assert_eq!(blocks, vec![value as u128]);

        let recomposed: i128 =
            BlockRecomposer::recompose_signed(blocks.into_iter(), MAX_BITS_PER_BLOCK, i128::BITS);
        assert_eq!(recomposed, value);
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
        for bits_per_block in 1..=MAX_BITS_PER_BLOCK {
            let blocks = BlockDecomposer::new(value, bits_per_block).collect::<Vec<_>>();

            let mut recomposer = BlockRecomposer::new(bits_per_block, U256::BITS);
            for block in blocks {
                recomposer.add_unmasked(block);
            }
            let recomposed: U256 = recomposer.value();
            assert_eq!(recomposed, value, "bits_per_block: {bits_per_block}");
        }
    }

    #[test]
    fn test_bit_block_decomposer_round_trip_every_bits_per_block_i256() {
        let value = -I256::from((
            0x1234_5678_9abc_def0u64,
            0xfedc_ba98_7654_3210u64,
            0x0f0f_0f0f_0f0f_0f0fu64,
            0x25a5_a5a5_a5a5_a5a5u64,
        ));
        for bits_per_block in 1..=MAX_BITS_PER_BLOCK {
            let blocks = BlockDecomposer::new(value, bits_per_block);
            let recomposed: I256 =
                BlockRecomposer::recompose_signed(blocks, bits_per_block, I256::BITS);
            assert_eq!(recomposed, value, "bits_per_block: {bits_per_block}");
        }
    }

    /// A zero width block has no meaningful semantics: it used to make the decomposer iterate
    /// forever, panic in `size_hint`, and make the recomposer discard all of its input
    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=128")]
    fn test_bit_block_decomposer_zero_bits_per_block() {
        let _ = BlockDecomposer::new(u16::MAX as u32, 0);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=128")]
    fn test_bit_block_recomposer_zero_bits_per_block() {
        let _ = BlockRecomposer::<u32>::new(0, u32::BITS);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=128")]
    fn test_bit_block_decomposer_too_many_bits_per_block() {
        let _ = BlockDecomposer::new(u16::MAX as u32, MAX_BITS_PER_BLOCK + 1);
    }

    #[test]
    #[should_panic(expected = "bits_per_block must be in 1..=128")]
    fn test_bit_block_recomposer_too_many_bits_per_block() {
        let _ = BlockRecomposer::<u32>::new(MAX_BITS_PER_BLOCK + 1, u32::BITS);
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

    /// Recomposing a value narrower than the clear type sign extends it
    #[test]
    fn test_bit_block_recomposer_signed_narrower_than_type() {
        // -1 on 6 bits, as 3 blocks of 2 bits
        let blocks = [3u64, 3, 3];
        let recomposed: i32 = BlockRecomposer::recompose_signed(blocks.iter().copied(), 2, 6);
        assert_eq!(recomposed, -1);

        // i8::MIN on 8 bits, as 4 blocks of 2 bits, into a wider type
        let blocks = [0u64, 0, 0, 2];
        let recomposed: i64 = BlockRecomposer::recompose_signed(blocks.iter().copied(), 2, 8);
        assert_eq!(recomposed, i64::from(i8::MIN));

        // 2 limbs of 4 bits but only 6 bits are part of the value: the top 2 bits of the last
        // limb are ignored and bit 5 is the sign
        let blocks = [0b1111u64, 0b1011];
        let recomposed: i16 =
            BlockRecomposer::recompose_signed_with_size(blocks.iter().copied(), 4, 6);
        assert_eq!(recomposed, -1);

        let blocks = [0b1111u64, 0b0110];
        let recomposed: i16 =
            BlockRecomposer::recompose_signed_with_size(blocks.iter().copied(), 4, 6);
        assert_eq!(recomposed, 0b10_1111 - 64);

        // No limbs at all is zero, it used to overflow the shift
        let recomposed: i16 = BlockRecomposer::recompose_signed(std::iter::empty::<u64>(), 4, 0);
        assert_eq!(recomposed, 0);
    }
}
