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
    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let mut mean = 0f64;
    // Still runs fast, about 1 billion runs which is exactly representable in float
    let runs = 1usize << 30;
    for _ in 0..runs {
        let val: u64 = rng.gen();
        let decomp = decomposer.decompose(val).next().unwrap();
        let value: i64 = decomp.value() as i64;
        mean += value as f64;
    }
    mean /= runs as f64;

    // To print with --nocapture to check in the terminal
    println!("mean={mean}");

    // This bound is not very tight or good, but as an unbalanced decomposition has a mean of about
    // 0.5 this will do
    assert!(mean.abs() < 0.2);
}
