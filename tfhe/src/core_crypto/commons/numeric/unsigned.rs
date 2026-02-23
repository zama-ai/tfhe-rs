use super::{CastFrom, CastInto, Numeric, SignedInteger, UnsignedNumeric};
use crate::core_crypto::prelude::OverflowingAdd;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

/// A trait shared by all the unsigned integer types.
pub trait UnsignedInteger:
    UnsignedNumeric
    + Ord
    + Eq
    + Add<Self, Output = Self>
    + AddAssign<Self>
    + Div<Self, Output = Self>
    + DivAssign<Self>
    + Mul<Self, Output = Self>
    + MulAssign<Self>
    + Rem<Self, Output = Self>
    + RemAssign<Self>
    + Sub<Self, Output = Self>
    + SubAssign<Self>
    + BitAnd<Self, Output = Self>
    + BitAndAssign<Self>
    + BitOr<Self, Output = Self>
    + BitOrAssign<Self>
    + BitXor<Self, Output = Self>
    + BitXorAssign<Self>
    + Not<Output = Self>
    + Shl<usize, Output = Self>
    + ShlAssign<usize>
    + Shr<usize, Output = Self>
    + ShrAssign<usize>
    + OverflowingAdd<Self, Output = Self>
    + CastFrom<Self::Signed>
    + CastFrom<f64>
    + CastInto<f64>
    + CastFrom<u128>
    + CastInto<u128>
    + std::fmt::Binary
    + From<bool>
{
    /// The signed type of the same precision.
    type Signed: SignedInteger<Unsigned = Self> + CastFrom<Self>;
    /// Return the leading zeros of the value.
    #[must_use]
    fn leading_zeros(self) -> u32;
    /// Compute an addition, modulo the max of the type.
    #[must_use]
    fn wrapping_add(self, other: Self) -> Self;
    /// Compute a subtraction, modulo the max of the type.
    #[must_use]
    fn wrapping_sub(self, other: Self) -> Self;
    /// Compute an addition, modulo a custom modulus.
    #[must_use]
    fn wrapping_add_custom_mod(self, other: Self, custom_modulus: Self) -> Self;
    /// Compute a subtraction, modulo a custom modulus.
    #[must_use]
    fn wrapping_sub_custom_mod(self, other: Self, custom_modulus: Self) -> Self;
    /// Compute a division, modulo the max of the type.
    #[must_use]
    fn wrapping_div(self, other: Self) -> Self;
    /// Compute a multiplication, modulo the max of the type.
    #[must_use]
    fn wrapping_mul(self, other: Self) -> Self;
    /// Compute a multiplication, modulo a custom modulus.
    #[must_use]
    fn wrapping_mul_custom_mod(self, other: Self, custom_modulus: Self) -> Self;
    /// Compute the remainder, modulo the max of the type.
    #[must_use]
    fn wrapping_rem(self, other: Self) -> Self;
    /// Compute a negation, modulo the max of the type.
    #[must_use]
    fn wrapping_neg(self) -> Self;
    /// Compute a negation, modulo the max of the type.
    #[must_use]
    fn wrapping_neg_custom_mod(self, custom_modulus: Self) -> Self;
    /// Compute an exponentiation, modulo the max of the type.
    #[must_use]
    fn wrapping_pow(self, exp: u32) -> Self;
    /// Panic free shift-left operation.
    #[must_use]
    fn wrapping_shl(self, rhs: u32) -> Self;
    /// Panic free shift-right operation.
    #[must_use]
    fn wrapping_shr(self, rhs: u32) -> Self;
    #[must_use]
    fn overflowing_sub(self, rhs: Self) -> (Self, bool);
    #[must_use]
    fn is_power_of_two(self) -> bool;
    #[must_use]
    fn next_power_of_two(self) -> Self;
    #[must_use]
    fn ilog2(self) -> u32;
    #[must_use]
    fn ceil_ilog2(self) -> u32 {
        // ilog2 returns the rounded down log2
        self.ilog2() + u32::from(!self.is_power_of_two())
    }
    #[must_use]
    fn to_le(self) -> Self;
    /// Integer division rounding up.
    #[must_use]
    fn div_ceil(self, divisor: Self) -> Self;
    /// Interpret the value as signed and apply an arithmetic right shift, sign extending like on a
    /// signed value.
    #[must_use]
    fn arithmetic_shr(self, rhs: usize) -> Self {
        self.into_signed().shr(rhs).into_unsigned()
    }
    /// Return the casting of the current value to the signed type of the same size.
    fn into_signed(self) -> Self::Signed;
    /// Return a bit representation of the integer, where blocks of length `block_length` are
    /// separated by whitespaces to increase the readability.
    fn to_bits_string(&self, block_length: usize) -> String;
}

macro_rules! implement {
    ($Type: tt, $SignedType:ty, $bits:expr) => {
        impl Numeric for $Type {
            const BITS: usize = $bits;
            const ZERO: Self = 0;
            const ONE: Self = 1;
            const TWO: Self = 2;
            const MAX: Self = <$Type>::MAX;
        }

        impl UnsignedNumeric for $Type {
            type NumericSignedType = $SignedType;
        }

        impl OverflowingAdd<Self> for $Type {
            type Output = Self;

            #[inline]
            fn overflowing_add(self, rhs: Self) -> (Self, bool) {
                self.overflowing_add(rhs)
            }
        }

        impl UnsignedInteger for $Type {
            type Signed = $SignedType;
            #[inline]
            fn into_signed(self) -> Self::Signed {
                Self::Signed::cast_from(self)
            }
            fn to_bits_string(&self, break_every: usize) -> String {
                let mut strn = match <$Type as Numeric>::BITS {
                    8 => format!("{:08b}", self),
                    16 => format!("{:016b}", self),
                    32 => format!("{:032b}", self),
                    64 => format!("{:064b}", self),
                    128 => format!("{:0128b}", self),
                    _ => unreachable!(),
                };
                for i in (1..(<$Type as Numeric>::BITS / break_every)).rev() {
                    strn.insert(i * break_every, ' ');
                }
                strn
            }
            #[inline]
            fn leading_zeros(self) -> u32 {
                self.leading_zeros()
            }
            #[inline]
            fn wrapping_add(self, other: Self) -> Self {
                self.wrapping_add(other)
            }
            #[inline]
            fn wrapping_sub(self, other: Self) -> Self {
                self.wrapping_sub(other)
            }
            #[inline]
            fn wrapping_add_custom_mod(self, other: Self, custom_modulus: Self) -> Self {
                self.wrapping_sub_custom_mod(
                    other.wrapping_neg_custom_mod(custom_modulus),
                    custom_modulus,
                )
            }
            #[inline]
            fn wrapping_sub_custom_mod(self, other: Self, custom_modulus: Self) -> Self {
                if self >= other {
                    self - other
                } else {
                    self.wrapping_sub(other).wrapping_add(custom_modulus)
                }
            }
            #[inline]
            fn wrapping_div(self, other: Self) -> Self {
                self.wrapping_div(other)
            }
            #[inline]
            fn wrapping_mul(self, other: Self) -> Self {
                self.wrapping_mul(other)
            }
            #[inline]
            fn wrapping_mul_custom_mod(self, other: Self, custom_modulus: Self) -> Self {
                if Self::BITS <= 64 {
                    let self_u128: u128 = self.cast_into();
                    let other_u128: u128 = other.cast_into();
                    let custom_modulus_u128: u128 = custom_modulus.cast_into();
                    self_u128
                        .wrapping_mul(other_u128)
                        .wrapping_rem(custom_modulus_u128)
                        .cast_into()
                } else {
                    todo!("wrapping_mul_custom_mod is not yet implemented for types wider than u64")
                }
            }
            #[inline]
            fn wrapping_rem(self, other: Self) -> Self {
                self.wrapping_rem(other)
            }
            #[inline]
            fn wrapping_neg(self) -> Self {
                self.wrapping_neg()
            }
            #[inline]
            fn wrapping_neg_custom_mod(self, custom_modulus: Self) -> Self {
                if self == Self::ZERO {
                    self
                } else {
                    custom_modulus - self
                }
            }
            #[inline]
            fn wrapping_shl(self, rhs: u32) -> Self {
                self.wrapping_shl(rhs)
            }
            #[inline]
            fn wrapping_shr(self, rhs: u32) -> Self {
                self.wrapping_shr(rhs)
            }
            #[inline]
            fn wrapping_pow(self, exp: u32) -> Self {
                self.wrapping_pow(exp)
            }
            #[inline]
            fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
                self.overflowing_sub(rhs)
            }
            #[inline]
            fn is_power_of_two(self) -> bool {
                self.is_power_of_two()
            }
            #[inline]
            fn next_power_of_two(self) -> Self {
                self.next_power_of_two()
            }
            #[inline]
            fn ilog2(self) -> u32 {
                self.ilog2()
            }
            #[inline]
            fn to_le(self) -> Self {
                self.to_le()
            }
            #[inline]
            fn div_ceil(self, divisor: Self) -> Self {
                self.div_ceil(divisor)
            }
        }
    };
}

implement!(u8, i8, 8);
implement!(u16, i16, 16);
implement!(u32, i32, 32);
implement!(u64, i64, 64);
implement!(u128, i128, 128);
implement!(usize, isize, usize::BITS as usize);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_uint8_binary_rep() {
        let a: u8 = 100;
        let b = a.to_bits_string(4);
        assert_eq!(b, "0110 0100".to_string());
    }

    #[test]
    fn test_uint16_binary_rep() {
        let a: u16 = 25702;
        let b = a.to_bits_string(4);
        assert_eq!(b, "0110 0100 0110 0110".to_string());
    }

    #[test]
    fn test_uint32_binary_rep() {
        let a: u32 = 1684411356;
        let b = a.to_bits_string(4);
        assert_eq!(b, "0110 0100 0110 0110 0001 0011 1101 1100".to_string());
    }

    #[test]
    fn test_uint64_binary_rep() {
        let a: u64 = 7_234_491_689_707_068_824;
        let b = a.to_bits_string(4);
        assert_eq!(
            b,
            "0110 0100 0110 0110 0001 0011 1101 1100 \
                       1001 1111 1000 0001 0101 1101 1001 1000"
                .to_string()
        );
    }

    #[test]
    fn test_uint128_binary_rep() {
        let a: u128 = 124_282_366_920_938_463_463_374_121_543_098_288_434;
        let b = a.to_bits_string(4);
        assert_eq!(
            b,
            "0101 1101 0111 1111 1110 1001 1100 0111 \
                       1000 1110 0110 0010 0000 0101 1011 0000 \
                       1011 1000 0011 0000 0001 0000 1001 0110 \
                       0011 1010 0110 1101 1100 1001 0011 0010"
                .to_string()
        );
    }

    #[test]
    fn test_wrapping_add_custom_mod() {
        use rand::Rng;
        let mut thread_rng = rand::rng();

        let moduli_to_test = vec![
            (1u128 << 64) - (1 << 32) + 1,
            (1u128 << 16) + 1,
            thread_rng.gen_range(1u128..u64::MAX as u128),
        ];

        for custom_modulus_u128 in moduli_to_test {
            let custom_modulus = custom_modulus_u128 as u64;
            let a = u64::MAX % custom_modulus;
            let b = u64::MAX % custom_modulus;

            let a_u128: u128 = a.into();
            let b_u128: u128 = b.into();

            let expected_res = ((a_u128 + b_u128) % custom_modulus_u128) as u64;

            let res = a.wrapping_add_custom_mod(b, custom_modulus);
            assert_eq!(expected_res, res);

            const NB_REPS: usize = 100_000_000;

            for _ in 0..NB_REPS {
                let a = thread_rng.gen::<u64>() % custom_modulus;
                let b = thread_rng.gen::<u64>() % custom_modulus;

                let a_u128: u128 = a.into();
                let b_u128: u128 = b.into();

                let expected_res = ((a_u128 + b_u128) % custom_modulus_u128) as u64;

                let res = a.wrapping_add_custom_mod(b, custom_modulus);
                assert_eq!(expected_res, res, "a: {a}, b: {b}");
            }
        }
    }

    #[test]
    fn test_wrapping_sub_custom_mod() {
        use rand::Rng;
        let mut thread_rng = rand::rng();

        let moduli_to_test = vec![
            (1u128 << 64) - (1 << 32) + 1,
            (1u128 << 16) + 1,
            thread_rng.gen_range(1u128..u64::MAX as u128),
        ];

        for custom_modulus_u128 in moduli_to_test {
            let custom_modulus = custom_modulus_u128 as u64;

            let a = 0u64;
            let b = u64::MAX % custom_modulus;

            let a_u128: u128 = a.into();
            let b_u128: u128 = b.into();

            let expected_res = ((a_u128
                .wrapping_add(custom_modulus_u128)
                .wrapping_sub(b_u128))
                % custom_modulus_u128) as u64;

            let res = a.wrapping_sub_custom_mod(b, custom_modulus);
            assert_eq!(expected_res, res);

            const NB_REPS: usize = 100_000_000;

            for _ in 0..NB_REPS {
                let a = thread_rng.gen::<u64>() % custom_modulus;
                let b = thread_rng.gen::<u64>() % custom_modulus;

                let a_u128: u128 = a.into();
                let b_u128: u128 = b.into();

                let expected_res = ((a_u128
                    .wrapping_add(custom_modulus_u128)
                    .wrapping_sub(b_u128))
                    % custom_modulus_u128) as u64;

                let res = a.wrapping_sub_custom_mod(b, custom_modulus);
                assert_eq!(expected_res, res, "a: {a}, b: {b}");
            }
        }
    }

    #[test]
    fn test_wrapping_mul_custom_mod() {
        use rand::Rng;
        let mut thread_rng = rand::rng();

        let moduli_to_test = vec![
            (1u128 << 64) - (1 << 32) + 1,
            (1u128 << 16) + 1,
            thread_rng.gen_range(1u128..u64::MAX as u128),
        ];

        for custom_modulus_u128 in moduli_to_test {
            let custom_modulus = custom_modulus_u128 as u64;
            let a = u64::MAX % custom_modulus;
            let b = u64::MAX % custom_modulus;

            let a_u128: u128 = a.into();
            let b_u128: u128 = b.into();

            let expected_res = ((a_u128 * b_u128) % custom_modulus_u128) as u64;

            let res = a.wrapping_mul_custom_mod(b, custom_modulus);
            assert_eq!(expected_res, res);

            const NB_REPS: usize = 100_000_000;

            for _ in 0..NB_REPS {
                let a = thread_rng.gen::<u64>() % custom_modulus;
                let b = thread_rng.gen::<u64>() % custom_modulus;

                let a_u128: u128 = a.into();
                let b_u128: u128 = b.into();

                let expected_res = ((a_u128 * b_u128) % custom_modulus_u128) as u64;

                let res = a.wrapping_mul_custom_mod(b, custom_modulus);
                assert_eq!(expected_res, res, "a: {a}, b: {b}");
            }
        }
    }
}
