use crate::core_crypto::commons::numeric::UnsignedInteger;

#[inline]
pub fn divide_round<Scalar: UnsignedInteger>(numerator: Scalar, denominator: Scalar) -> Scalar {
    // // Does the following without overflowing (which can happen with the addition of denom / 2)
    // (numerator + denominator / Scalar::TWO) / denominator

    // div and rem should be computed in a single instruction on most CPUs for native types < u128
    let (div, rem) = (numerator / denominator, numerator % denominator);
    div + Scalar::from(rem >= (denominator >> 1))
}

pub fn modular_distance_custom_mod<Scalar: UnsignedInteger>(
    x: Scalar,
    y: Scalar,
    modulus: Scalar,
) -> Scalar {
    if y >= x {
        let diff = y - x;
        let x_u128: u128 = x.cast_into();
        let y_u128: u128 = y.cast_into();
        let modulus_u128: u128 = modulus.cast_into();
        let wrap_diff = Scalar::cast_from(modulus_u128 + x_u128 - y_u128);
        diff.min(wrap_diff)
    } else {
        modular_distance_custom_mod(y, x, modulus)
    }
}

#[cfg(test)]
mod test {
    use super::divide_round;

    #[test]
    fn test_divide_round() {
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

            let rounded = (num / denom).round();
            let expected_rounded_u64: u64 = rounded as u64;

            let num_u64: u64 = num as u64;
            let denom_u64: u64 = denom as u64;

            // sanity check
            assert_eq!(num, num_u64 as f64);
            assert_eq!(denom, denom_u64 as f64);

            let rounded_u64 = divide_round(num_u64, denom_u64);

            assert_eq!(expected_rounded_u64, rounded_u64);
        }
    }
}
