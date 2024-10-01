use crate::u256;

#[inline(always)]
pub(crate) const fn mul128_u32(lowbits: u64, d: u32) -> u32 {
    ((lowbits as u128 * d as u128) >> 64) as u32
}

#[inline(always)]
pub(crate) const fn mul128_u64(lowbits: u128, d: u64) -> u64 {
    let mut bottom_half = (lowbits & 0xFFFF_FFFF_FFFF_FFFF) * d as u128;
    bottom_half >>= 64;
    let top_half = (lowbits >> 64) * d as u128;
    let both_halves = bottom_half + top_half;
    (both_halves >> 64) as u64
}

#[inline(always)]
pub(crate) const fn mul256_u128(lowbits: u256, d: u128) -> u128 {
    lowbits.mul_u256_u128(d).1
}

#[inline(always)]
pub(crate) const fn mul256_u64(lowbits: u256, d: u64) -> u64 {
    lowbits.mul_u256_u64(d).1
}

/// Divisor representing a 32bit denominator.
#[derive(Copy, Clone, Debug)]
pub struct Div32 {
    pub double_reciprocal: u128,
    pub single_reciprocal: u64,
    pub divisor: u32,
}

/// Divisor representing a 64bit denominator.
#[derive(Copy, Clone, Debug)]
pub struct Div64 {
    pub double_reciprocal: u256,
    pub single_reciprocal: u128,
    pub divisor: u64,
}

impl Div32 {
    /// Returns the division structure holding the given divisor.
    ///
    /// # Panics
    /// Panics if the divisor is zero or one.
    pub const fn new(divisor: u32) -> Self {
        assert!(divisor > 1);
        let single_reciprocal = (u64::MAX / divisor as u64) + 1;
        let double_reciprocal = (u128::MAX / divisor as u128) + 1;

        Self {
            double_reciprocal,
            single_reciprocal,
            divisor,
        }
    }

    /// Returns the quotient of the division of `n` by `d`.
    #[inline(always)]
    pub const fn div(n: u32, d: Self) -> u32 {
        mul128_u32(d.single_reciprocal, n)
    }

    /// Returns the remainder of the division of `n` by `d`.
    #[inline(always)]
    pub const fn rem(n: u32, d: Self) -> u32 {
        let low_bits = d.single_reciprocal.wrapping_mul(n as u64);
        mul128_u32(low_bits, d.divisor)
    }

    /// Returns the quotient of the division of `n` by `d`.
    #[inline(always)]
    pub const fn div_u64(n: u64, d: Self) -> u64 {
        mul128_u64(d.double_reciprocal, n)
    }

    /// Returns the remainder of the division of `n` by `d`.
    #[inline(always)]
    pub const fn rem_u64(n: u64, d: Self) -> u32 {
        let low_bits = d.double_reciprocal.wrapping_mul(n as u128);
        mul128_u64(low_bits, d.divisor as u64) as u32
    }

    /// Returns the internal divisor as an integer.
    #[inline(always)]
    pub const fn divisor(&self) -> u32 {
        self.divisor
    }
}

impl Div64 {
    /// Returns the division structure holding the given divisor.
    ///
    /// # Panics
    /// Panics if the divisor is zero or one.
    pub const fn new(divisor: u64) -> Self {
        assert!(divisor > 1);
        let single_reciprocal = ((u128::MAX) / divisor as u128) + 1;
        let double_reciprocal = u256::MAX
            .div_rem_u256_u64(divisor)
            .0
            .overflowing_add(u256 {
                x0: 1,
                x1: 0,
                x2: 0,
                x3: 0,
            })
            .0;

        Self {
            double_reciprocal,
            single_reciprocal,
            divisor,
        }
    }

    /// Returns the quotient of the division of `n` by `d`.
    #[inline(always)]
    pub const fn div(n: u64, d: Self) -> u64 {
        mul128_u64(d.single_reciprocal, n)
    }

    /// Returns the remainder of the division of `n` by `d`.
    #[inline(always)]
    pub const fn rem(n: u64, d: Self) -> u64 {
        let low_bits = d.single_reciprocal.wrapping_mul(n as u128);
        mul128_u64(low_bits, d.divisor)
    }

    /// Returns the quotient of the division of `n` by `d`.
    #[inline(always)]
    pub const fn div_u128(n: u128, d: Self) -> u128 {
        mul256_u128(d.double_reciprocal, n)
    }

    /// Returns the remainder of the division of `n` by `d`.
    #[inline(always)]
    pub const fn rem_u128(n: u128, d: Self) -> u64 {
        let low_bits = d.double_reciprocal.wrapping_mul_u256_u128(n);
        mul256_u64(low_bits, d.divisor)
    }

    /// Returns the internal divisor as an integer.
    #[inline(always)]
    pub const fn divisor(&self) -> u64 {
        self.divisor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_div64() {
        for _ in 0..1000 {
            let divisor = loop {
                let d = random();
                if d > 1 {
                    break d;
                }
            };

            let div = Div64::new(divisor);
            let n = random();
            let m = random();
            assert_eq!(Div64::div(m, div), m / divisor);
            assert_eq!(Div64::rem(m, div), m % divisor);
            assert_eq!(Div64::div_u128(n, div), n / divisor as u128);
            assert_eq!(Div64::rem_u128(n, div) as u128, n % divisor as u128);
        }
    }

    #[test]
    fn test_div32() {
        for _ in 0..1000 {
            let divisor = loop {
                let d = random();
                if d > 1 {
                    break d;
                }
            };

            let div = Div32::new(divisor);
            let n = random();
            let m = random();
            assert_eq!(Div32::div(m, div), m / divisor);
            assert_eq!(Div32::rem(m, div), m % divisor);
            assert_eq!(Div32::div_u64(n, div), n / divisor as u64);
            assert_eq!(Div32::rem_u64(n, div) as u64, n % divisor as u64);
        }
    }
}
