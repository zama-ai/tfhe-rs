use super::Numeric;
use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};

/// A trait shared by all the floating point types.
pub trait FloatingPoint:
    Numeric
    + Neg<Output = Self>
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
{
    /// Number of significant digits in base 2.
    const MANTISSA_DIGITS: usize;

    /// Raise a float to an integer power.
    #[must_use]
    fn powi(self, power: i32) -> Self;

    /// Round the float to the closest integer.
    #[must_use]
    fn round(self) -> Self;

    /// Keep the fractional part of the number.
    #[must_use]
    fn fract(self) -> Self;

    /// Remainder of the euclidean division.
    #[must_use]
    fn rem_euclid(self, rhs: Self) -> Self;

    /// Return the square root of the input float.
    #[must_use]
    fn sqrt(self) -> Self;

    /// Return the natural logarithm of the input float.
    #[must_use]
    fn ln(self) -> Self;

    /// Return the absolute value of the input float.
    #[must_use]
    fn abs(self) -> Self;

    /// Return the floor value of the input float.
    #[must_use]
    fn floor(self) -> Self;

    /// Return a bit representation of the float, with the sign, exponent, and mantissa bits
    /// separated by whitespaces for increased readability.
    fn to_bit_string(&self) -> String;
}

macro_rules! implement {
    ($Type: tt, $bits:expr) => {
        impl Numeric for $Type {
            const BITS: usize = $bits;
            const ZERO: Self = 0.;
            const ONE: Self = 1.;
            const TWO: Self = 2.;
            const MAX: Self = <$Type>::MAX;
        }
        impl FloatingPoint for $Type {
            const MANTISSA_DIGITS: usize = $Type::MANTISSA_DIGITS as usize;
            #[inline]
            fn powi(self, power: i32) -> Self {
                self.powi(power)
            }
            #[inline]
            fn round(self) -> Self {
                self.round()
            }
            #[inline]
            fn fract(self) -> Self {
                self.fract()
            }
            #[inline]
            fn rem_euclid(self, rhs: Self) -> Self {
                self.rem_euclid(rhs)
            }
            #[inline]
            fn sqrt(self) -> Self {
                self.sqrt()
            }
            #[inline]
            fn ln(self) -> Self {
                self.ln()
            }
            #[inline]
            fn abs(self) -> Self {
                self.abs()
            }
            #[inline]
            fn floor(self) -> Self {
                self.floor()
            }
            fn to_bit_string(&self) -> String {
                if Self::BITS == 32 {
                    let mut bit_string = format!("{:032b}", self.to_bits());
                    bit_string.insert(1, ' ');
                    bit_string.insert(10, ' ');
                    format!("{}", bit_string)
                } else {
                    let mut bit_string = format!("{:064b}", self.to_bits());
                    bit_string.insert(1, ' ');
                    bit_string.insert(13, ' ');
                    format!("{}", bit_string)
                }
            }
        }
    };
}

implement!(f64, 64);
implement!(f32, 32);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_f64_binary_rep() {
        let a = 1123214.4321432_f64;
        let b = a.to_bit_string();
        assert_eq!(
            b,
            "0 10000010011 0001001000111000111001101110101000001110111111001111".to_string()
        );
    }

    #[test]
    fn test_f32_binary_rep() {
        let a = -1.276_663_9e27_f32;
        let b = a.to_bit_string();
        assert_eq!(b, "1 11011001 00001000000000100000011".to_string());
    }
}
