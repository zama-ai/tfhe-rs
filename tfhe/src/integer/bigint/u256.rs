use crate::core_crypto::prelude::Numeric;

pub type U256 = super::static_unsigned::StaticUnsignedBigInt<4>;

impl From<(u128, u128)> for U256 {
    fn from(v: (u128, u128)) -> Self {
        let mut converted = [u64::ZERO; 4];

        converted[0] = (v.0 & u128::from(u64::MAX)) as u64;
        converted[1] = (v.0 >> 64) as u64;
        converted[2] = (v.1 & u128::from(u64::MAX)) as u64;
        converted[3] = (v.1 >> 64) as u64;

        Self(converted)
    }
}

impl U256 {
    pub fn to_low_high_u128(self) -> (u128, u128) {
        let low = self.0[0] as u128 | ((self.0[1] as u128) << 64);
        let high = self.0[2] as u128 | ((self.0[3] as u128) << 64);
        (low, high)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{u64_with_even_bits_set, u64_with_odd_bits_set};
    use super::*;
    use crate::core_crypto::prelude::OverflowingAdd;
    use rand::Rng;
    use std::panic::catch_unwind;

    #[test]
    fn test_const() {
        assert_eq!(U256::BITS, 256);
    }

    #[test]
    fn test_u64_even_odd_bits() {
        let all_even_bits_set = u64_with_even_bits_set();
        let all_odd_bits_set = u64_with_odd_bits_set();

        assert_ne!(all_odd_bits_set, all_even_bits_set);

        assert_eq!(all_even_bits_set.rotate_right(1), all_odd_bits_set);
        assert_eq!(all_even_bits_set, all_odd_bits_set.rotate_left(1));
    }

    #[test]
    fn test_bitand() {
        let all_even_bits_set = U256::from([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256::from([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set & all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set & all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set & all_odd_bits_set, U256::ZERO);
    }

    #[test]
    fn test_bitor() {
        let all_even_bits_set = U256::from([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256::from([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set | all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set | all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set | all_odd_bits_set, U256::MAX);
    }

    #[test]
    fn test_bitxor() {
        let all_even_bits_set = U256::from([u64_with_even_bits_set(); 4]);
        let all_odd_bits_set = U256::from([u64_with_odd_bits_set(); 4]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set ^ all_odd_bits_set, U256::ZERO);
        assert_eq!(all_even_bits_set ^ all_even_bits_set, U256::ZERO);
        assert_eq!(all_even_bits_set ^ all_odd_bits_set, U256::MAX);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!U256::ZERO.is_power_of_two());
        assert!(!U256::MAX.is_power_of_two());
        assert!(!U256::from(8329842348123u64).is_power_of_two());

        for i in 0..U256::BITS {
            assert!((U256::ONE << i).is_power_of_two());
        }
    }

    #[test]
    fn test_ilog2() {
        assert!(catch_unwind(|| { U256::ZERO.ilog2() }).is_err());

        assert_eq!(U256::MAX.ilog2(), 255);
        assert_eq!(
            U256::from(8329842348123u64).ilog2(),
            8329842348123u64.ilog2()
        );

        assert_eq!(
            U256::from(8320912948329842348123u128).ilog2(),
            8320912948329842348123u128.ilog2()
        );

        assert_eq!(
            U256::from(2323912928329942718123u128).ilog2(),
            2323912928329942718123u128.ilog2()
        );

        for i in 0..U256::BITS {
            assert_eq!((U256::ONE << i).ilog2(), i);
        }
    }

    #[test]
    fn test_mul() {
        let u64_max = U256::from(u64::MAX);
        let expected = u64::MAX as u128 * u64::MAX as u128;
        assert_eq!(u64_max * u64_max, U256::from(expected));

        let mut rng = rand::rng();
        for _ in 0..5 {
            let a = rng.gen::<u64>();
            let b = rng.gen::<u64>();

            let res = U256::from(a) * U256::from(b);
            let expected = a as u128 * b as u128;
            assert_eq!(res, U256::from(expected));
        }

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * u128_max;
        let expected = U256::from((1u128, 340282366920938463463374607431768211454u128));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::from(3284723894u64);
        let expected = U256::from((340282366920938463463374607428483487562u128, 3284723893u128));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::from(u64::MAX);
        let expected = U256::from((
            340282366920938463444927863358058659841u128,
            18446744073709551614u128,
        ));
        assert_eq!(res, expected);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::ZERO;
        assert_eq!(res, U256::ZERO);

        let u128_max = U256::from(u128::MAX);
        let res = u128_max * U256::ONE;
        assert_eq!(res, u128_max);
    }

    #[test]
    fn test_div_rem() {
        let u64_max = U256::from(u64::MAX);
        let (expected_q, expected_r) = (u64::MAX / u64::MAX, u64::MAX % u64::MAX);
        assert_eq!(u64_max / u64_max, U256::from(expected_q));
        assert_eq!(u64_max % u64_max, U256::from(expected_r));

        let mut rng = rand::rng();
        for _ in 0..5 {
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();

            let res_q = U256::from(a) / U256::from(b);
            let res_r = U256::from(a) % U256::from(b);
            let expected_q = a / b;
            let expected_r = a % b;
            assert_eq!(res_q, U256::from(expected_q));
            assert_eq!(res_r, U256::from(expected_r));
        }

        let u128_max = U256::from(u128::MAX);
        let res_q = u128_max / U256::from(3284723894u64);
        let res_r = u128_max % U256::from(3284723894u64);
        let expected_q = U256::from(103595424730374145554705368314u128);
        let expected_r = U256::from(701916739u128);
        assert_eq!(res_q, expected_q);
        assert_eq!(res_r, expected_r);

        let u256_max = U256::MAX;
        let res_q = u256_max / U256::ONE;
        let res_r = u256_max % U256::ONE;
        assert_eq!(res_q, u256_max);
        assert_eq!(res_r, U256::ZERO);

        let a = U256::from((
            98789923123891239238309u128,
            166153499473114484112975882535043072u128,
        ));
        let b = U256::from((12937934723948230984120983u128, 2u128));
        let expected_q = U256::from(83076749736555662718753084335755618u128);
        let expected_r = U256::from((169753858020977627805335755091673007575u128, 1u128));
        assert_eq!(a / b, expected_q);
        assert_eq!(a % b, expected_r);
        assert_eq!(b / a, U256::ZERO);
        assert_eq!(b % a, b);

        let a = U256::from((283984787393485348590806231, 18446744073709551616));
        let b = U256::from((53249231281381239239045, 134217728));
        let expected_q = U256::from(137438953471u128);
        let expected_r = U256::from((340275048402601999976919705355157542492, 134217727));
        assert_eq!(a / b, expected_q);
        assert_eq!(a % b, expected_r);
        assert_eq!(b / a, U256::ZERO);
        assert_eq!(b % a, b);
    }

    #[test]
    fn test_add_wrap_around() {
        assert_eq!(U256::MAX + U256::from(1u32), U256::MIN);
    }

    #[test]
    fn test_overflowing_add() {
        let (r, o) = U256::MAX.overflowing_add(U256::from(1u32));
        assert_eq!(r, U256::MIN);
        assert!(o);

        let (r, o) = U256::MAX.overflowing_add(U256::from(0u32));
        assert_eq!(r, U256::MAX);
        assert!(!o);
    }

    #[test]
    fn test_sub_wrap_around() {
        assert_eq!(U256::MIN - U256::from(1u32), U256::MAX);
    }

    #[test]
    fn test_bitnot() {
        assert_eq!(!U256::MAX, U256::MIN);
        assert_eq!(!U256::MIN, U256::MAX);

        // To prove we are testing the correct thing
        assert_eq!(!u128::MAX, u128::MIN);
        assert_eq!(!u128::MIN, u128::MAX);
    }

    #[test]
    fn test_shl_limits() {
        assert_eq!(U256::ONE << 256u32, U256::ONE << (256 % U256::BITS));
        assert_eq!(U256::ONE << 257u32, U256::ONE << (257 % U256::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(1u128.wrapping_shl(128), 1u128 << (128 % u128::BITS));
        assert_eq!(1u128.wrapping_shl(129), 1u128 << (129 % u128::BITS));
    }

    #[test]
    #[allow(clippy::identity_op)]
    fn test_shr_limits() {
        assert_eq!(U256::MAX >> 256u32, U256::MAX >> (256 % U256::BITS));
        assert_eq!(U256::MAX >> 257u32, U256::MAX >> (257 % U256::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(u128::MAX.wrapping_shr(128), u128::MAX >> (128 % u128::BITS));
        assert_eq!(u128::MAX.wrapping_shr(129), u128::MAX >> (129 % u128::BITS));
    }

    #[test]
    fn test_shr() {
        assert_eq!(U256::MAX >> 128u32, U256::from(u128::MAX));

        let input = (u64::MAX as u128) << 64;
        let a = U256::from(input);

        assert_eq!(a >> 1u32, U256::from(input >> 1));
    }

    #[test]
    fn test_shl() {
        let input = (u64::MAX as u128) << 64;
        let a = U256::from(input);

        // input a u128 with its 64 MSB set to one
        // so left shifting it by one will move one bit
        // to the next inner u64 block
        assert_eq!(a << 1u32, U256::from((input << 1, 1u128)));
    }

    #[test]
    fn test_le_byte_slice() {
        // Create a u128 where each bytes stores its index:
        // u128 as &[u8] = [0u8, 1 , 2, 3, .., 15]
        let low = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let high = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));

        let mut le_bytes = vec![0u8; 32];
        le_bytes[..16].copy_from_slice(low.to_le_bytes().as_slice());
        le_bytes[16..].copy_from_slice(high.to_le_bytes().as_slice());

        let mut b = U256::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_le_byte_slice(le_bytes.as_slice());

        assert_eq!(b, U256::from((low, high)));

        let mut le_bytes_2 = vec![0u8; 32];
        b.copy_to_le_byte_slice(&mut le_bytes_2);

        assert_eq!(le_bytes_2, le_bytes);
    }

    #[test]
    fn test_be_byte_slice() {
        let low = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let high = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));

        let mut be_bytes = vec![0u8; 32];
        be_bytes[16..].copy_from_slice(low.to_be_bytes().as_slice());
        be_bytes[..16].copy_from_slice(high.to_be_bytes().as_slice());

        let mut b = U256::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_be_byte_slice(be_bytes.as_slice());

        assert_eq!(b, U256::from((low, high)));

        let mut be_bytes_2 = vec![0u8; 32];
        b.copy_to_be_byte_slice(&mut be_bytes_2);

        assert_eq!(be_bytes_2, be_bytes);
    }
}
