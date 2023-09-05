//! Miscellaneous algorithms.

use crate::core_crypto::prelude::*;

#[inline]
pub fn divide_ceil<Scalar>(numerator: Scalar, denominator: Scalar) -> Scalar
where
    Scalar: UnsignedInteger,
{
    // Should be a single instruction on x86 and likely other processors
    let (div, rem) = (numerator / denominator, numerator % denominator);
    div + Scalar::from(rem != Scalar::ZERO)
}

#[inline]
pub fn divide_round<Scalar: UnsignedInteger>(numerator: Scalar, denominator: Scalar) -> Scalar {
    // // Does the following without overflowing (which can happen with the addition of denom / 2)
    // (numerator + denominator / Scalar::TWO) / denominator

    // Add the half interval mapping
    // [denominator * (numerator - 1/2); denominator * (numerator + 1/2)[ to
    // [denominator * numerator; denominator * (numerator + 1)[
    // Dividing by denominator gives numerator which is what we want

    // div and rem should be computed in a single instruction on most CPUs for native types < u128
    let (div, rem) = (numerator / denominator, numerator % denominator);
    div + Scalar::from(rem >= (denominator >> 1))
}

#[inline]
pub fn divide_round_to_u128_custom_mod<Scalar>(
    numerator: Scalar,
    denominator: Scalar,
    modulus: u128,
) -> u128
where
    Scalar: UnsignedInteger,
{
    let numerator_128: u128 = numerator.cast_into();
    let half_denominator: u128 = (denominator / Scalar::TWO).cast_into();
    let denominator_128: u128 = denominator.cast_into();
    // That's the rounding
    ((numerator_128 + half_denominator) % modulus) / denominator_128
}

pub fn odd_modular_inverse_pow_2<Scalar>(odd_value_to_invert: Scalar, log2_modulo: usize) -> Scalar
where
    Scalar: UnsignedInteger,
{
    let t = log2_modulo.ilog2() + if log2_modulo.is_power_of_two() { 0 } else { 1 };
    let mut y = Scalar::ONE;
    let e = odd_value_to_invert;

    for i in 1..=t {
        // 1 << (1 << i) == 2 ^ {2 ^ i}
        let curr_mod = Scalar::ONE.shl(1 << i);
        // y = y * (2 - y * e) mod 2 ^ {2 ^ i}
        // Here using wrapping ops is ok as the modulus used is a power of 2, as long as 2 ^ {2 ^ i}
        // is smaller than Scalar::BITS, we are good to go, the discarded values would not have been
        // Used anyways, and 2 ^ {2 ^ i} is compatible with a native modulus
        y = (y.wrapping_mul(Scalar::TWO.wrapping_sub(y.wrapping_mul(e)))).wrapping_rem(curr_mod);
    }

    y.wrapping_rem(Scalar::ONE.shl(log2_modulo))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_divide_funcs() {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        const NB_TESTS: usize = 1_000_000_000;
        const SCALING: f64 = u64::MAX as f64;
        for _ in 0..NB_TESTS {
            let num: f64 = rng.gen();
            let mut denom = 0.0f64;
            while denom == 0.0f64 {
                denom = rng.gen();
            }

            let num = (num * SCALING).round();
            let denom = (denom * SCALING).round();

            let div_f64 = num / denom;

            let rounded = div_f64.round();
            let expected_rounded_u64: u64 = rounded as u64;

            let num_u64: u64 = num as u64;
            let denom_u64: u64 = denom as u64;

            // sanity check
            assert_eq!(num, num_u64 as f64);
            assert_eq!(denom, denom_u64 as f64);

            let rounded = divide_round(num_u64, denom_u64);

            assert_eq!(expected_rounded_u64, rounded);

            let ceiled = div_f64.ceil();
            let expected_ceiled_u64: u64 = ceiled as u64;

            let ceiled = divide_ceil(num_u64, denom_u64);
            assert_eq!(expected_ceiled_u64, ceiled);
        }
    }
}
