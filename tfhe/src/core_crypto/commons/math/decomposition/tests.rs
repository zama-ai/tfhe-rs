use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::math::random::{RandomGenerable, Uniform};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{Numeric, SignedInteger, UnsignedInteger};
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use crate::core_crypto::commons::test_tools::{any_uint, any_usize, random_usize_between};
use crate::core_crypto::commons::traits::CastInto;
use std::fmt::Debug;

fn valid_decomposers<T: UnsignedInteger>() -> Vec<SignedDecomposer<T>> {
    let mut valid_decomposers = vec![];
    for base_log in (1..T::BITS).map(DecompositionBaseLog) {
        for level_count in (1..T::BITS).map(DecompositionLevelCount) {
            if base_log.0 * level_count.0 < T::BITS {
                valid_decomposers.push(SignedDecomposer::new(base_log, level_count));
                continue;
            }

            // If the current base_log * level_count exceeds T::BITS then as level_count increases
            // all the decomposers after it won't be valid, so break
            break;
        }
    }

    valid_decomposers
}

fn test_decompose_recompose<T: UnsignedInteger + Debug + RandomGenerable<Uniform>>()
where
    <T as UnsignedInteger>::Signed: Debug + SignedInteger,
{
    let valid_decomposers = valid_decomposers::<T>();
    let runs_per_decomposer = divide_ceil(100_000, valid_decomposers.len());

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
    let runs_per_decomposer = divide_ceil(100_000, valid_decomposers.len());

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
    let runs_per_decomposer = divide_ceil(100_000, valid_decomposers.len());

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

// Return a random decomposition valid for the size of the T type.
fn random_decomp_non_native<T: UnsignedInteger>(
    ciphertext_modulus: CiphertextModulus<T>,
) -> SignedDecomposerNonNative<T> {
    let mut base_log;
    let mut level_count;
    loop {
        base_log = random_usize_between(1..T::BITS);
        level_count = random_usize_between(1..T::BITS);
        if base_log * level_count < T::BITS {
            break;
        }
    }
    SignedDecomposerNonNative::new(
        DecompositionBaseLog(base_log),
        DecompositionLevelCount(level_count),
        ciphertext_modulus,
    )
}

fn test_round_to_closest_representable_non_native<T: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<T>,
) {
    // Manage limit cases
    {
        let log_b = any_usize();
        let level_max = any_usize();
        let bits = T::BITS;
        let log_b = (log_b % ((bits / 4) - 1)) + 1;
        let level_count = (level_max % 4) + 1;
        let rep_bits: usize = log_b * level_count;

        let base_to_the_level_u128 = 1u128 << rep_bits;
        let smallest_representable_u128 =
            ciphertext_modulus.get_custom_modulus() / base_to_the_level_u128;
        let sub_smallest_representable_u128 = smallest_representable_u128 / 2;
        // Compute an epsilon that should not change the result of a closest representable
        let epsilon_u128 = any_uint::<u128>() % sub_smallest_representable_u128;

        // Around 0
        let val = T::ZERO;

        let decomposer = SignedDecomposerNonNative::new(
            DecompositionBaseLog(log_b),
            DecompositionLevelCount(level_count),
            ciphertext_modulus,
        );

        let val_u128: u128 = val.cast_into();
        let val_plus_epsilon: T = val_u128
            .wrapping_add(epsilon_u128)
            .wrapping_rem(ciphertext_modulus.get_custom_modulus())
            .cast_into();

        let closest = decomposer.closest_representable(val_plus_epsilon);
        assert_eq!(
            val, closest,
            "\n val_plus_epsilon:          {val_plus_epsilon:064b}, \n \
        expected_closest:           {val:064b}, \n \
        closest:                    {closest:064b}\n \
        decomp_base_log: {}, decomp_level_count: {}",
            decomposer.base_log, decomposer.level_count
        );

        let val_minus_epsilon: T = val_u128
            .wrapping_add(ciphertext_modulus.get_custom_modulus())
            .wrapping_sub(epsilon_u128)
            .wrapping_rem(ciphertext_modulus.get_custom_modulus())
            .cast_into();

        let closest = decomposer.closest_representable(val_minus_epsilon);
        assert_eq!(
            val, closest,
            "\n val_minus_epsilon:          {val_minus_epsilon:064b}, \n \
        expected_closest:           {val:064b}, \n \
        closest:                    {closest:064b}\n \
        decomp_base_log: {}, decomp_level_count: {}",
            decomposer.base_log, decomposer.level_count
        );
    }

    for _ in 0..1000 {
        let log_b = any_usize();
        let level_max = any_usize();
        let bits = T::BITS;
        let log_b = (log_b % ((bits / 4) - 1)) + 1;
        let level_count = (level_max % 4) + 1;
        let rep_bits: usize = log_b * level_count;

        let base_to_the_level_u128 = 1u128 << rep_bits;
        let base_to_the_level = T::ONE << rep_bits;
        let smallest_representable_u128 =
            ciphertext_modulus.get_custom_modulus() / base_to_the_level_u128;
        let smallest_representable: T = smallest_representable_u128.cast_into();
        let sub_smallest_representable_u128 = smallest_representable_u128 / 2;
        // Compute an epsilon that should not change the result of a closest representable
        let epsilon_u128 = any_uint::<u128>() % sub_smallest_representable_u128;

        let multiple_of_smallest_representable = any_uint::<T>() % base_to_the_level;
        let val = multiple_of_smallest_representable * smallest_representable;

        let decomposer = SignedDecomposerNonNative::new(
            DecompositionBaseLog(log_b),
            DecompositionLevelCount(level_count),
            ciphertext_modulus,
        );

        let val_u128: u128 = val.cast_into();
        let val_plus_epsilon: T = val_u128
            .wrapping_add(epsilon_u128)
            .wrapping_rem(ciphertext_modulus.get_custom_modulus())
            .cast_into();

        let closest = decomposer.closest_representable(val_plus_epsilon);
        assert_eq!(
            val, closest,
            "\n val_plus_epsilon:          {val_plus_epsilon:064b}, \n \
            expected_closest:           {val:064b}, \n \
            closest:                    {closest:064b}\n \
            decomp_base_log: {}, decomp_level_count: {}",
            decomposer.base_log, decomposer.level_count
        );

        let val_minus_epsilon: T = val_u128
            .wrapping_add(ciphertext_modulus.get_custom_modulus())
            .wrapping_sub(epsilon_u128)
            .wrapping_rem(ciphertext_modulus.get_custom_modulus())
            .cast_into();

        let closest = decomposer.closest_representable(val_minus_epsilon);
        assert_eq!(
            val, closest,
            "\n val_minus_epsilon:          {val_minus_epsilon:064b}, \n \
            expected_closest:           {val:064b}, \n \
            closest:                    {closest:064b}\n \
            decomp_base_log: {}, decomp_level_count: {}",
            decomposer.base_log, decomposer.level_count
        );
    }
}

#[test]
fn test_round_to_closest_representable_non_native_u64() {
    test_round_to_closest_representable_non_native::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

fn test_round_to_closest_twice_non_native<T: UnsignedTorus + Debug>(
    ciphertext_modulus: CiphertextModulus<T>,
) {
    for _ in 0..1000 {
        let decomp = random_decomp_non_native(ciphertext_modulus);
        let input: T = any_uint();

        let rounded_once = decomp.closest_representable(input);
        let rounded_twice = decomp.closest_representable(rounded_once);
        assert_eq!(rounded_once, rounded_twice);
    }
}

#[test]
fn test_round_to_closest_twice_non_native_u64() {
    test_round_to_closest_twice_non_native::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}
