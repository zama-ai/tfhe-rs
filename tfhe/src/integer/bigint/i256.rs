use crate::core_crypto::prelude::Numeric;

pub type I256 = super::static_signed::StaticSignedBigInt<4>;

impl From<(u128, u128)> for I256 {
    fn from(v: (u128, u128)) -> Self {
        let mut converted = [u64::ZERO; 4];

        converted[0] = (v.0 & u128::from(u64::MAX)) as u64;
        converted[1] = (v.0 >> 64) as u64;
        converted[2] = (v.1 & u128::from(u64::MAX)) as u64;
        converted[3] = (v.1 >> 64) as u64;

        Self(converted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::prelude::CastFrom;
    use rand::Rng;

    #[test]
    fn test_const() {
        assert_eq!(I256::BITS, 256);
        assert_eq!(I256::ZERO, I256::from([0, 0, 0, 0]));
        assert_eq!(I256::ONE, I256::from([1, 0, 0, 0]));
        assert_eq!(I256::TWO, I256::from([2, 0, 0, 0]));
        assert_eq!(
            I256::MAX,
            I256::from([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1])
        );
        assert_eq!(I256::MIN, I256::from([0, 0, 0, 1u64 << 63]));
    }

    #[test]
    fn test_i128_conversion() {
        let input = I256::from(-1i128);
        assert_eq!(input.0, [u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        assert_eq!(i128::cast_from(input), -1i128);

        // 0b11111111...1000...00
        // input is 64 0s in MSB, 64 1s in LSB
        let input = i128::from(i64::MIN) << 1;
        let big = I256::from(input);
        assert_eq!(
            big.0,
            [(i64::MIN << 1) as u64, u64::MAX, u64::MAX, u64::MAX]
        );
        assert_eq!(i128::cast_from(big), input);
    }

    #[test]
    fn test_add_wrap_around() {
        assert_eq!(I256::MAX + I256::ONE, I256::MIN);
        assert_eq!(I256::MIN + (-I256::ONE), I256::MAX);
    }

    #[test]
    fn test_sub_wrap_around() {
        assert_eq!(I256::MIN - I256::ONE, I256::MAX);
        assert_eq!(I256::MAX - (-I256::ONE), I256::MIN);
    }

    #[test]
    fn test_add() {
        assert_eq!(I256::from(-1i32) + I256::ONE, I256::ZERO);
    }

    #[test]
    fn test_sub() {
        assert_eq!(I256::ONE - I256::ONE, I256::ZERO);
        assert_eq!(I256::ONE - I256::from(-1i32), I256::TWO);
    }

    #[test]
    fn test_shl_limits() {
        assert_eq!(
            I256::ONE << I256::BITS,
            I256::ONE << (I256::BITS % I256::BITS)
        );
        assert_eq!(
            I256::ONE << (I256::BITS + 1),
            I256::ONE << ((I256::BITS + 1) % I256::BITS)
        );

        // We aim to have same behaviour as rust native types
        assert_eq!(1i128.wrapping_shl(128), 1i128 << (128 % i128::BITS));
        assert_eq!(1i128.wrapping_shl(129), 1i128 << (129 % i128::BITS));
    }

    #[test]
    fn test_shl() {
        let input = i64::MIN as i128;
        let a = I256::from(input);

        assert_eq!(a << 1u32, I256::from(input << 1));
    }

    #[test]
    fn test_shr() {
        let input = i128::MIN;
        let a = I256::from(input);
        assert_eq!(a >> 1u32, I256::from(input >> 1));

        let a = I256::MIN;
        // We expect (MSB) 110............0 (LSB)
        assert_eq!(
            a >> 1u32,
            // 3 is '11'
            I256::from([0, 0, 0, 3 << 62])
        );
    }

    #[test]
    fn test_div_rem() {
        let i64_max = I256::from(i64::MAX);
        let (expected_q, expected_r) = (i64::MAX / i64::MAX, i64::MAX % i64::MAX);
        assert_eq!(i64_max / i64_max, I256::from(expected_q));
        assert_eq!(i64_max % i64_max, I256::from(expected_r));

        let mut rng = rand::rng();
        for _ in 0..5 {
            let a = rng.gen::<i128>();
            let b = rng.gen::<i128>();

            let res_q = I256::from(a) / I256::from(b);
            let res_r = I256::from(a) % I256::from(b);
            let expected_q = a / b;
            let expected_r = a % b;
            assert_eq!(res_q, I256::from(expected_q));
            assert_eq!(res_r, I256::from(expected_r));
        }

        let i256_max = I256::MAX;
        let res_q = i256_max / I256::ONE;
        let res_r = i256_max % I256::ONE;
        assert_eq!(res_q, i256_max);
        assert_eq!(res_r, I256::ZERO);
        // These values come from python
        let a = I256::from((
            330090607680070657243007942644838587352u128,
            16697987949408356462265050424072830869u128,
        ));
        let minus_a = !a + I256::ONE;
        let b = I256::from((
            260561703368011588548711105617059109455u128,
            115613679824413351007243677446092220483u128,
        ));
        let expected_q = I256::from(0);
        let expected_r = minus_a;
        assert_eq!(minus_a / b, expected_q);
        assert_eq!(minus_a % b, expected_r);
        assert_eq!(b / minus_a, I256::from(-6i32));
        assert_eq!(
            b % minus_a,
            I256::from((
                321712258813218425870911094338636854079,
                15425752127963212233653374901655235263u128
            ))
        );
    }

    #[test]
    fn test_mul() {
        // These values come from python
        let a = I256::from((
            330090607680070657243007942644838587352u128,
            16697987949408356462265050424072830869u128,
        ));
        let minus_a = !a + I256::ONE;
        let b = I256::from((
            260561703368011588548711105617059109455u128,
            115613679824413351007243677446092220483u128,
        ));

        let expected_result = I256::from((
            117308708923619114563105829751976081496u128,
            21961921777201805456110035736645139690u128,
        ));
        assert_eq!(minus_a * b, expected_result);
    }
}
