use super::{CastFrom, CastInto, Numeric, SignedNumeric, UnsignedInteger};
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

/// A trait shared by all the signed integer types.
pub trait SignedInteger:
    SignedNumeric
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
    + CastFrom<f64>
    + CastInto<f64>
{
    /// The unsigned type of the same precicion
    type Unsigned: UnsignedInteger<Signed = Self> + CastFrom<Self>;

    /// Return the casting of the current value to the unsigned type of the same size.
    fn into_unsigned(self) -> Self::Unsigned;

    /// Return a bit representation of the integer, where blocks of length `block_length` are
    /// separated by whitespaces to increase the readability.
    fn to_bits_string(&self, block_length: usize) -> String;
}

macro_rules! implement {
    ($Type: tt, $UnsignedType:ty, $bits:expr) => {
        impl Numeric for $Type {
            const BITS: usize = $bits;
            const ZERO: Self = 0;
            const ONE: Self = 1;
            const TWO: Self = 2;
            const MAX: Self = <$Type>::MAX;
        }

        impl SignedNumeric for $Type {}

        impl SignedInteger for $Type {
            type Unsigned = $UnsignedType;
            #[inline]
            fn into_unsigned(self) -> Self::Unsigned {
                Self::Unsigned::cast_from(self)
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
        }
    };
}

implement!(i8, u8, 8);
implement!(i16, u16, 16);
implement!(i32, u32, 32);
implement!(i64, u64, 64);
implement!(i128, u128, 128);
implement!(isize, usize, isize::BITS as usize);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sint8_binary_rep() {
        let a: i8 = -100;
        let b = a.to_bits_string(4);
        assert_eq!(b, "1001 1100".to_string());
    }

    #[test]
    fn test_sint16_binary_rep() {
        let a: i16 = -25702;
        let b = a.to_bits_string(4);
        assert_eq!(b, "1001 1011 1001 1010".to_string());
    }

    #[test]
    fn test_sint32_binary_rep() {
        let a: i32 = -1684411356;
        let b = a.to_bits_string(4);
        assert_eq!(b, "1001 1011 1001 1001 1110 1100 0010 0100".to_string());
    }

    #[test]
    fn test_sint64_binary_rep() {
        let a: i64 = -7_234_491_689_707_068_824;
        let b = a.to_bits_string(4);
        assert_eq!(
            b,
            "1001 1011 1001 1001 1110 1100 0010 0011 \
                       0110 0000 0111 1110 1010 0010 0110 1000"
                .to_string()
        );
    }

    #[test]
    fn test_sint128_binary_rep() {
        let a: i128 = -124_282_366_920_938_463_463_374_121_543_098_288_434;
        let b = a.to_bits_string(4);
        assert_eq!(
            b,
            "1010 0010 1000 0000 0001 0110 0011 1000 \
                       0111 0001 1001 1101 1111 1010 0100 1111 \
                       0100 0111 1100 1111 1110 1111 0110 1001 \
                       1100 0101 1001 0010 0011 0110 1100 1110"
                .to_string()
        );
    }
}
