use crate::core_crypto::prelude::CastFrom;

pub type U512 = super::static_unsigned::StaticUnsignedBigInt<8>;

impl From<(u128, u128, u128, u128)> for U512 {
    fn from((value0, value1, value2, value3): (u128, u128, u128, u128)) -> Self {
        Self([
            (value0 & u128::from(u64::MAX)) as u64,
            (value0 >> 64) as u64,
            (value1 & u128::from(u64::MAX)) as u64,
            (value1 >> 64) as u64,
            (value2 & u128::from(u64::MAX)) as u64,
            (value2 >> 64) as u64,
            (value3 & u128::from(u64::MAX)) as u64,
            (value3 >> 64) as u64,
        ])
    }
}

impl CastFrom<crate::integer::U256> for U512 {
    fn cast_from(input: crate::integer::U256) -> Self {
        Self([input.0[0], input.0[1], input.0[2], input.0[3], 0, 0, 0, 0])
    }
}

#[cfg(test)]
mod tests {
    use super::super::{u64_with_even_bits_set, u64_with_odd_bits_set};
    use super::*;
    use std::panic::catch_unwind;

    #[test]
    fn test_const() {
        assert_eq!(U512::BITS, 512);
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
        let all_even_bits_set = U512::from([u64_with_even_bits_set(); 8]);
        let all_odd_bits_set = U512::from([u64_with_odd_bits_set(); 8]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set & all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set & all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set & all_odd_bits_set, U512::ZERO);
    }

    #[test]
    fn test_bitor() {
        let all_even_bits_set = U512::from([u64_with_even_bits_set(); 8]);
        let all_odd_bits_set = U512::from([u64_with_odd_bits_set(); 8]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set | all_odd_bits_set, all_odd_bits_set);
        assert_eq!(all_even_bits_set | all_even_bits_set, all_even_bits_set);
        assert_eq!(all_even_bits_set | all_odd_bits_set, U512::MAX);
    }

    #[test]
    fn test_bitxor() {
        let all_even_bits_set = U512::from([u64_with_even_bits_set(); 8]);
        let all_odd_bits_set = U512::from([u64_with_odd_bits_set(); 8]);

        assert_ne!(all_odd_bits_set, all_even_bits_set);
        assert_eq!(all_odd_bits_set ^ all_odd_bits_set, U512::ZERO);
        assert_eq!(all_even_bits_set ^ all_even_bits_set, U512::ZERO);
        assert_eq!(all_even_bits_set ^ all_odd_bits_set, U512::MAX);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!U512::ZERO.is_power_of_two());
        assert!(!U512::MAX.is_power_of_two());
        assert!(!U512::from(8329842348123u64).is_power_of_two());

        for i in 0..U512::BITS {
            assert!((U512::ONE << i).is_power_of_two());
        }
    }

    #[test]
    fn test_ilog2() {
        assert!(catch_unwind(|| { U512::ZERO.ilog2() }).is_err());

        assert_eq!(U512::MAX.ilog2(), 511);
        assert_eq!(
            U512::from(8329842348123u64).ilog2(),
            8329842348123u64.ilog2()
        );

        assert_eq!(
            U512::from(8320912948329842348123u128).ilog2(),
            8320912948329842348123u128.ilog2()
        );

        assert_eq!(
            U512::from(2323912928329942718123u128).ilog2(),
            2323912928329942718123u128.ilog2()
        );

        for i in 0..U512::BITS {
            assert_eq!((U512::ONE << i).ilog2(), i);
        }
    }

    #[test]
    fn test_add_wrap_around() {
        assert_eq!(U512::MAX + U512::from(1u32), U512::MIN);
    }

    #[test]
    fn test_sub_wrap_around() {
        assert_eq!(U512::MIN - U512::from(1u32), U512::MAX);
    }

    #[test]
    fn test_bitnot() {
        assert_eq!(!U512::MAX, U512::MIN);
        assert_eq!(!U512::MIN, U512::MAX);

        // To prove we are testing the correct thing
        assert_eq!(!u128::MAX, u128::MIN);
        assert_eq!(!u128::MIN, u128::MAX);
    }

    #[test]
    fn test_shl_limits() {
        assert_eq!(U512::ONE << 512u32, U512::ONE << (512u32 % U512::BITS));
        assert_eq!(U512::ONE << 513u32, U512::ONE << (513u32 % U512::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(1u128.wrapping_shl(128), 1u128 << (128 % u128::BITS));
        assert_eq!(1u128.wrapping_shl(129), 1u128 << (129 % u128::BITS));
    }

    #[test]
    fn test_shr_limits() {
        assert_eq!(U512::MAX >> 512u32, U512::MAX >> (512u32 % U512::BITS));
        assert_eq!(U512::MAX >> 513u32, U512::MAX >> (513u32 % U512::BITS));

        // We aim to have same behaviour as rust native types
        assert_eq!(u128::MAX.wrapping_shr(128), u128::MAX >> (128 % u128::BITS));
        assert_eq!(u128::MAX.wrapping_shr(129), u128::MAX >> (129 % u128::BITS));
    }

    #[test]
    fn test_div_rem() {
        let a = U512::from([
            14069555808489703714,
            3908590842307590452,
            9855978718424440147,
            13896218366640697882,
            12201638264960915474,
            18057167307258037924,
            3883391760393286388,
            13564609649884598296,
        ]);

        let b = U512::from([
            13572348791597489471,
            13066001923991081603,
            15152085515464322039,
            5769296961266547928,
            4345306966403270406,
            14861723594231331435,
            12450980561267212543,
            13551971813301316858,
        ]);

        let expected_d = U512::from([1, 0, 0, 0, 0, 0, 0, 0]);

        let expected_r = U512::from([
            497207016892214243,
            9289332992026060465,
            13150637276669669723,
            8126921405374149953,
            7856331298557645068,
            3195443713026706489,
            9879155272835625461,
            12637836583281437,
        ]);

        let d = a / b;
        let r = a % b;
        assert_eq!(d, expected_d);
        assert_eq!(r, expected_r);

        let a = U512::from([
            3916138088563380184,
            11471505607132531241,
            11764394181449351249,
            3009844506142576707,
            5954421029540908215,
            493654323038934126,
            6030625548640772789,
            12886253569586615920,
        ]);

        let b = U512::from([
            15734844303166734968,
            18157387122068819778,
            7947001930394566593,
            11842813283329086337,
            13455790396220372987,
            16771555752599506498,
            12734235444062124671,
            984106389135760972,
        ]);

        let expected_d = U512::from([13, 0, 0, 0, 0, 0, 0, 0]);

        let expected_r = U512::from([
            2277346958200893376,
            15233145978462045124,
            687089454867743607,
            15073968486250418865,
            15496586615771575535,
            3824358423759969034,
            6506261439219116598,
            92870510821723275,
        ]);

        let d = a / b;
        let r = a % b;
        assert_eq!(d, expected_d);
        assert_eq!(r, expected_r);
    }

    #[test]
    fn test_mul() {
        let a = U512::from([
            14069555808489703714,
            3908590842307590452,
            9855978718424440147,
            13896218366640697882,
            12201638264960915474,
            18057167307258037924,
            3883391760393286388,
            13564609649884598296,
        ]);

        let b = U512::from([
            13572348791597489471,
            13066001923991081603,
            15152085515464322039,
            5769296961266547928,
            4345306966403270406,
            14861723594231331435,
            12450980561267212543,
            13551971813301316858,
        ]);

        let expected_result = U512::from([
            4156026748591446366,
            5494944174831101103,
            18238946655790339985,
            7541952578616659641,
            13348226788602217476,
            12942926403796405442,
            8114377417900506174,
            14085526951817456422,
        ]);

        let result = a * b;
        assert_eq!(result, expected_result);

        let a = U512::from([
            3916138088563380184,
            11471505607132531241,
            11764394181449351249,
            3009844506142576707,
            5954421029540908215,
            493654323038934126,
            6030625548640772789,
            12886253569586615920,
        ]);

        let b = U512::from([
            15734844303166734968,
            18157387122068819778,
            7947001930394566593,
            11842813283329086337,
            13455790396220372987,
            16771555752599506498,
            12734235444062124671,
            984106389135760972,
        ]);

        let expected_result = U512::from([
            959128001500093760,
            16717200888364732243,
            4987629022208480162,
            13025491345955469749,
            3380626290232599789,
            4346647371474752052,
            13274445184588134645,
            9592080887013845353,
        ]);

        let result = a * b;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_le_byte_slice() {
        // Create a u128 where each bytes stores its index:
        // u128 as &[u8] = [0u8, 1 , 2, 3, .., 15]
        let v0 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let v1 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));
        let v2 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 32 + i as u8));
        let v3 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 48 + i as u8));

        let mut le_bytes = vec![0u8; 64];
        le_bytes[..16].copy_from_slice(v0.to_le_bytes().as_slice());
        le_bytes[16..32].copy_from_slice(v1.to_le_bytes().as_slice());
        le_bytes[32..48].copy_from_slice(v2.to_le_bytes().as_slice());
        le_bytes[48..].copy_from_slice(v3.to_le_bytes().as_slice());

        let mut b = U512::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_le_byte_slice(le_bytes.as_slice());

        assert_eq!(b, U512::from((v0, v1, v2, v3)));

        let mut le_bytes_2 = vec![0u8; 64];
        b.copy_to_le_byte_slice(&mut le_bytes_2);

        assert_eq!(le_bytes_2, le_bytes);
    }

    #[test]
    fn test_be_byte_slice() {
        let v0 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| i as u8));
        let v1 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 16 + i as u8));
        let v2 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 32 + i as u8));
        let v3 = u128::from_le_bytes(core::array::from_fn::<u8, 16, _>(|i| 48 + i as u8));

        let mut be_bytes = vec![0u8; 64];
        be_bytes[..16].copy_from_slice(v3.to_be_bytes().as_slice());
        be_bytes[16..32].copy_from_slice(v2.to_be_bytes().as_slice());
        be_bytes[32..48].copy_from_slice(v1.to_be_bytes().as_slice());
        be_bytes[48..].copy_from_slice(v0.to_be_bytes().as_slice());

        let mut b = U512::from(1u128 << 64); // To make sure copy cleans self
        b.copy_from_be_byte_slice(be_bytes.as_slice());

        assert_eq!(b, U512::from((v0, v1, v2, v3)));

        let mut be_bytes_2 = vec![0u8; 64];
        b.copy_to_be_byte_slice(&mut be_bytes_2);

        assert_eq!(be_bytes_2, be_bytes);
    }
}
