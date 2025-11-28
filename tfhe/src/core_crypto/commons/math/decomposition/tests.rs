use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::math::random::{RandomGenerable, Uniform};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{Numeric, SignedInteger, UnsignedInteger};
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use crate::core_crypto::commons::test_tools::any_uint;
use crate::core_crypto::commons::traits::CastInto;
use std::fmt::Debug;

pub const NB_TESTS: usize = 10_000_000;

fn valid_decomposers<T: UnsignedInteger>() -> Vec<SignedDecomposer<T>> {
    let mut valid_decomposers = vec![];
    for base_log in (1..T::BITS).map(DecompositionBaseLog) {
        for level_count in (1..T::BITS).map(DecompositionLevelCount) {
            if base_log.0 * level_count.0 < T::BITS {
                valid_decomposers.push(SignedDecomposer::new(base_log, level_count));
            } else {
                // If the current base_log * level_count exceeds T::BITS then as level_count
                // increases all the decomposers after it won't be valid, so break
                break;
            }
        }
    }

    valid_decomposers
}

fn test_decompose_recompose<T: UnsignedInteger + Debug + RandomGenerable<Uniform>>()
where
    <T as UnsignedInteger>::Signed: Debug + SignedInteger,
{
    let valid_decomposers = valid_decomposers::<T>();
    let runs_per_decomposer = NB_TESTS.div_ceil(valid_decomposers.len());

    for decomposer in valid_decomposers {
        for _ in 0..runs_per_decomposer {
            let input = any_uint::<T>();

            // Decompose/recompose test
            for (term_idx, term) in decomposer.decompose(input).enumerate() {
                assert_eq!(term.level().0, decomposer.level_count - term_idx);
                let signed_term = term.value().into_signed();
                // Shift by base_log - 1 directly to avoid overflows
                let half_basis = T::Signed::ONE << (decomposer.base_log - 1);
                assert!(
                    -half_basis <= signed_term,
                    "-half_basis={:?}, signed_term = {signed_term:?}",
                    -half_basis,
                );
                assert!(
                    signed_term <= half_basis,
                    "signed_term={signed_term:?}, half_basis = {half_basis:?}",
                );
            }
            let closest = decomposer.closest_representable(input);
            assert_eq!(
                closest,
                decomposer.recompose(decomposer.decompose(input)).unwrap()
            );
        }
    }
}

#[test]
fn test_decompose_recompose_u32() {
    test_decompose_recompose::<u32>();
}

#[test]
fn test_decompose_recompose_u64() {
    test_decompose_recompose::<u64>();
}

fn test_round_to_closest_representable<T: UnsignedTorus>() {
    let valid_decomposers = valid_decomposers::<T>();
    let runs_per_decomposer = NB_TESTS.div_ceil(valid_decomposers.len());

    // Checks that the decomposing and recomposing a value brings the closest representable
    for decomposer in valid_decomposers {
        for _ in 0..runs_per_decomposer {
            let input = any_uint::<T>();

            let rounded = decomposer.closest_representable(input);

            let epsilon =
                (T::ONE << (T::BITS - (decomposer.base_log * decomposer.level_count) - 1)) / T::TWO;
            // Adding/removing an epsilon should not change the closest representable
            assert_eq!(
                rounded,
                decomposer.closest_representable(rounded.wrapping_add(epsilon))
            );
            assert_eq!(
                rounded,
                decomposer.closest_representable(rounded.wrapping_sub(epsilon))
            );
        }
    }
}

#[test]
fn test_round_to_closest_representable_u32() {
    test_round_to_closest_representable::<u32>();
}

#[test]
fn test_round_to_closest_representable_u64() {
    test_round_to_closest_representable::<u64>();
}

fn test_round_to_closest_twice<T: UnsignedTorus + Debug>() {
    let valid_decomposers = valid_decomposers::<T>();
    let runs_per_decomposer = NB_TESTS.div_ceil(valid_decomposers.len());

    for decomposer in valid_decomposers {
        for _ in 0..runs_per_decomposer {
            let input = any_uint::<T>();

            // Round twice test, should not change the returned value
            let rounded_once = decomposer.closest_representable(input);
            let rounded_twice = decomposer.closest_representable(rounded_once);
            assert_eq!(rounded_once, rounded_twice);
        }
    }
}

#[test]
fn test_round_to_closest_twice_u32() {
    test_round_to_closest_twice::<u32>();
}

#[test]
fn test_round_to_closest_twice_u64() {
    test_round_to_closest_twice::<u64>();
}

fn valid_non_native_decomposers<T: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<T>,
) -> Vec<SignedDecomposerNonNative<T>> {
    let ciphertext_modulus_bit_count: usize = ciphertext_modulus
        .get_custom_modulus()
        .ceil_ilog2()
        .try_into()
        .unwrap();
    let mut valid_decomposers = vec![];

    for base_log in (1..ciphertext_modulus_bit_count).map(DecompositionBaseLog) {
        for level_count in (1..ciphertext_modulus_bit_count).map(DecompositionLevelCount) {
            if base_log.0 * level_count.0 < ciphertext_modulus_bit_count {
                valid_decomposers.push(SignedDecomposerNonNative::new(
                    base_log,
                    level_count,
                    ciphertext_modulus,
                ));
            } else {
                // If the current base_log * level_count exceeds ciphertext_modulus_bit_count then
                // as level_count increases all the decomposers after it won't be
                // valid, so break
                break;
            }
        }
    }

    valid_decomposers
}

fn test_decompose_recompose_non_native<T: UnsignedTorus>(ciphertext_modulus: CiphertextModulus<T>) {
    let ciphertext_modulus_as_t: T = ciphertext_modulus.get_custom_modulus().cast_into();

    let valid_decomposers = valid_non_native_decomposers::<T>(ciphertext_modulus);
    let runs_per_decomposer = NB_TESTS.div_ceil(valid_decomposers.len());

    for decomposer in valid_decomposers {
        for _ in 0..runs_per_decomposer {
            let input = any_uint::<T>() % ciphertext_modulus_as_t;

            let dec = decomposer.decompose(input);
            let rec = decomposer.recompose(dec).unwrap();

            println!("input={input:?}");
            println!("rec={rec:?}");
            println!("closest={:?}", decomposer.closest_representable(input));

            assert_eq!(decomposer.closest_representable(input), rec);
        }
    }
}

#[test]
fn test_decompose_recompose_non_native_solinas_u64() {
    test_decompose_recompose_non_native::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

#[test]
fn test_decompose_recompose_non_native_edge_mod_round_up_u64() {
    test_decompose_recompose_non_native::<u64>(CiphertextModulus::try_new((1 << 48) + 1).unwrap());
}

#[test]
fn test_single_level_decompose_balanced() {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(12), DecompositionLevelCount(1));

    assert_eq!(
        decomposer.level_count().0,
        1,
        "This test is only valid if the decomposition level count is 1"
    );
    let base_log = decomposer.base_log().0;
    assert!(base_log < u64::BITS as usize);
    let bits_for_random_value = base_log + 1;
    let mut sum = 0i64;
    for val in 0..(1u64 << bits_for_random_value) {
        let val = val << (u64::BITS as usize - bits_for_random_value);
        let decomp = decomposer.decompose(val).next().unwrap();
        let value: i64 = decomp.value() as i64;
        sum = sum.checked_add(value).unwrap();
    }

    // We expect an average value of 0 so the sum is also 0
    assert_eq!(sum, 0);
}

#[test]
fn test_decomposition_edge_case_sign_handling() {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(17), DecompositionLevelCount(3));
    let val: u64 = 0x8000_00e3_55b0_c827;

    let rounded = decomposer.closest_representable(val);
    let recomp = decomposer.recompose(decomposer.decompose(val)).unwrap();
    let decomp = decomposer.decompose(val);
    assert_eq!(rounded, recomp);

    let expected = [44422i64, 909, -65536];

    for (term, expect) in decomp.zip(expected) {
        assert_eq!(term.value() as i64, expect, "Problem with term {term:?}");
    }
}

#[test]
fn test_decomposition_edge_case_sign_handling_u128() {
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(40), DecompositionLevelCount(3));
    let val: u128 = 170141183460604905165246226680529368983;

    let rounded = decomposer.closest_representable(val);
    let recomp = decomposer.recompose(decomposer.decompose(val)).unwrap();
    let decomp = decomposer.decompose(val);
    assert_eq!(rounded, recomp);

    let expected = [-421613125320i128, 482008863255, -549755813888];

    for (term, expect) in decomp.zip(expected) {
        assert_eq!(term.value() as i128, expect, "Problem with term {term:?}");
    }
}

#[test]
fn test_recompose_exhaustive() {
    let base_log = DecompositionBaseLog(10);
    let level = DecompositionLevelCount(3);
    let decomposer = SignedDecomposer::new(base_log, level);

    assert!(
        decomposer.level_count().0 > 1,
        "This test expects more than 1 level in the decomposer"
    );
    assert!(
        decomposer.level_count().0 * decomposer.base_log().0 < u32::BITS as usize,
        "This test works on u32 values, \
        the number of bits decomposed must be strictly smaller than 32"
    );

    let mut total = 0i64;

    for val in 0..=u32::MAX {
        let recomp = decomposer.recompose(decomposer.decompose(val)).unwrap();
        let rounded = decomposer.closest_representable(val);

        assert_eq!(rounded, recomp);

        for term in decomposer.decompose(val) {
            // First cast to i32 to have the interpretation of the u32 as a signed value
            let val_i32 = term.value() as i32;
            // Then convert to i64 to have signed values with extra capacity to avoid potential
            // overflows when summing terms
            let val_i64: i64 = val_i32 as i64;

            // Crash on overflow, it would make the test results invalid
            total = total.checked_add(val_i64).unwrap();
        }
    }

    // We expect an average value of 0, so the sum of term should also be 0
    assert_eq!(total, 0);
}
