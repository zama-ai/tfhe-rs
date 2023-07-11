use crate::core_crypto::algorithms::{divide_round, torus_abs_diff_custom_mod};
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::math::random::{RandomGenerable, Uniform};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{Numeric, SignedInteger, UnsignedInteger};
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use crate::core_crypto::commons::test_tools::{any_uint, any_usize, random_usize_between};
use std::fmt::Debug;

// Return a random decomposition valid for the size of the T type.
fn random_decomp<T: UnsignedInteger>() -> SignedDecomposer<T> {
    let mut base_log;
    let mut level_count;
    loop {
        base_log = random_usize_between(2..T::BITS);
        level_count = random_usize_between(2..T::BITS);
        if base_log * level_count < T::BITS {
            break;
        }
    }
    SignedDecomposer::new(
        DecompositionBaseLog(base_log),
        DecompositionLevelCount(level_count),
    )
}

fn test_decompose_recompose<T: UnsignedInteger + Debug + RandomGenerable<Uniform>>()
where
    <T as UnsignedInteger>::Signed: Debug + SignedInteger,
{
    // Checks that the decomposing and recomposing a value brings the closest representable
    for _ in 0..100_000 {
        let decomposer = random_decomp::<T>();
        let input = any_uint::<T>();
        for term in decomposer.decompose(input) {
            assert!(1 <= term.level().0);
            assert!(term.level().0 <= decomposer.level_count);
            let signed_term = term.value().into_signed();
            let half_basis = (T::Signed::ONE << decomposer.base_log) / T::TWO.into_signed();
            assert!(-half_basis <= signed_term);
            assert!(signed_term <= half_basis);
        }
        let closest = decomposer.closest_representable(input);
        assert_eq!(
            closest,
            decomposer.recompose(decomposer.decompose(closest)).unwrap()
        );
    }
}

#[test]
fn test_decompose_recompose_u32() {
    test_decompose_recompose::<u32>()
}

#[test]
fn test_decompose_recompose_u64() {
    test_decompose_recompose::<u64>()
}

fn test_round_to_closest_representable<T: UnsignedTorus>() {
    for _ in 0..1000 {
        let log_b = any_usize();
        let level_max = any_usize();
        let val = any_uint::<T>();
        let delta = any_uint::<T>();
        let bits = T::BITS;
        let log_b = (log_b % ((bits / 4) - 1)) + 1;
        let level_max = (level_max % 4) + 1;
        let bit: usize = log_b * level_max;

        let val = val << (bits - bit);
        let delta = delta >> (bit + 1);

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(log_b),
            DecompositionLevelCount(level_max),
        );

        assert_eq!(
            val,
            decomposer.closest_representable(val.wrapping_add(delta))
        );
        assert_eq!(
            val,
            decomposer.closest_representable(val.wrapping_sub(delta))
        );
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
    for _ in 0..1000 {
        let decomp = random_decomp();
        let input: T = any_uint();

        let rounded_once = decomp.closest_representable(input);
        let rounded_twice = decomp.closest_representable(rounded_once);
        assert_eq!(rounded_once, rounded_twice);
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
        base_log = random_usize_between(2..T::BITS);
        level_count = random_usize_between(2..T::BITS);
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
    {
        let log_b = any_usize();
        let level_max = any_usize();
        let bits = T::BITS;
        let base_log = (log_b % ((bits / 4) - 1)) + 1;
        let level_count = (level_max % 4) + 1;

        let val = T::ZERO;
        let smallest_representable = divide_round(
            ciphertext_modulus.get_custom_modulus(),
            1u128 << (base_log * level_count),
        );
        let sub_smallest_representable = T::cast_from(smallest_representable / 2);
        let epsilon = any_uint::<T>() % sub_smallest_representable;
        let ciphertext_modulus_as_t = T::cast_from(ciphertext_modulus.get_custom_modulus());

        let decomposer = SignedDecomposerNonNative::new(
            DecompositionBaseLog(base_log),
            DecompositionLevelCount(level_count),
            ciphertext_modulus,
        );

        let val_plus_epsilon = val.wrapping_add_custom_mod(epsilon, ciphertext_modulus_as_t);
        for term in decomposer.decompose(val_plus_epsilon) {
            assert!(1 <= term.level().0);
            assert!(term.level().0 <= decomposer.level_count);
            let term = term.value();
            let half_basis = (T::ONE << decomposer.base_log) / T::TWO;

            let abs_term = if term > ciphertext_modulus_as_t / T::TWO {
                ciphertext_modulus_as_t - term
            } else {
                term
            };

            assert!(abs_term <= half_basis);
        }
        assert_eq!(val, decomposer.closest_representable(val_plus_epsilon));

        let val_minus_epsilon = val.wrapping_sub_custom_mod(epsilon, ciphertext_modulus_as_t);
        for term in decomposer.decompose(val_minus_epsilon) {
            assert!(1 <= term.level().0);
            assert!(term.level().0 <= decomposer.level_count);
            let term = term.value();
            let half_basis = (T::ONE << decomposer.base_log) / T::TWO;

            let abs_term = if term > ciphertext_modulus_as_t / T::TWO {
                ciphertext_modulus_as_t - term
            } else {
                term
            };

            assert!(abs_term <= half_basis);
        }
        assert_eq!(val, decomposer.closest_representable(val_minus_epsilon));
    }

    for _ in 0..1000 {
        let log_b = any_usize();
        let level_max = any_usize();
        let val = any_uint::<T>();
        let bits = T::BITS;
        let base_log = (log_b % ((bits / 4) - 1)) + 1;
        let level_count = (level_max % 4) + 1;
        let rep_bits: usize = base_log * level_count;

        let val = val << (bits - rep_bits);
        let smallest_representable = divide_round(
            ciphertext_modulus.get_custom_modulus(),
            1u128 << (base_log * level_count),
        );
        let sub_smallest_representable = T::cast_from(smallest_representable / 2);
        let epsilon = any_uint::<T>() % sub_smallest_representable;
        let ciphertext_modulus_as_t = T::cast_from(ciphertext_modulus.get_custom_modulus());

        let decomposer = SignedDecomposerNonNative::new(
            DecompositionBaseLog(base_log),
            DecompositionLevelCount(level_count),
            ciphertext_modulus,
        );

        {
            let val_plus_epsilon = val.wrapping_add_custom_mod(epsilon, ciphertext_modulus_as_t);
            for term in decomposer.decompose(val_plus_epsilon) {
                assert!(1 <= term.level().0);
                assert!(term.level().0 <= decomposer.level_count);
                let term = term.value();
                let half_basis = (T::ONE << decomposer.base_log) / T::TWO;

                let abs_term = if term > ciphertext_modulus_as_t / T::TWO {
                    ciphertext_modulus_as_t - term
                } else {
                    term
                };

                assert!(abs_term <= half_basis);
            }
            let closest = decomposer.closest_representable(val_plus_epsilon);
            let distance = torus_abs_diff_custom_mod(val, closest, ciphertext_modulus_as_t);
            let distance_f64: f64 = distance.cast_into();
            // -1 as we don't divide exactly for prime Q
            let max_correct_bits: usize = base_log * level_count - 1;
            let max_err_bits: usize = T::BITS - max_correct_bits;
            assert!(
            distance_f64.log2() <= max_err_bits as f64,
            "base_log={base_log}, level_count={level_count}, val={val:064b}, closest={closest:064b}"
        );
        }

        {
            let val_minus_epsilon = val.wrapping_sub_custom_mod(epsilon, ciphertext_modulus_as_t);
            for term in decomposer.decompose(val_minus_epsilon) {
                assert!(1 <= term.level().0);
                assert!(term.level().0 <= decomposer.level_count);
                let term = term.value();
                let half_basis = (T::ONE << decomposer.base_log) / T::TWO;

                let abs_term = if term > ciphertext_modulus_as_t / T::TWO {
                    ciphertext_modulus_as_t - term
                } else {
                    term
                };

                assert!(abs_term <= half_basis);
            }
            let closest = decomposer.closest_representable(val_minus_epsilon);
            let distance = torus_abs_diff_custom_mod(val, closest, ciphertext_modulus_as_t);
            let distance_f64: f64 = distance.cast_into();
            // -1 as we don't divide exactly for prime Q
            let max_correct_bits: usize = base_log * level_count - 1;
            let max_err_bits: usize = T::BITS - max_correct_bits;
            assert!(
            distance_f64.log2() <= max_err_bits as f64,
            "base_log={base_log}, level_count={level_count}, val={val:064b}, closest={closest:064b}"
        );
        }
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

#[test]
fn test_decomposer_mod_smaller_2_to_63() {
    let ciphertext_modulus = CiphertextModulus::<u64>::try_new(1 << 62).unwrap();
    // 0010_0111_10...0
    let value_to_decompose_non_native =
        (1u64 << 61) + (1 << 58) + (1 << 57) + (1 << 56) + (1 << 55);
    let base_log = DecompositionBaseLog(3);
    let level_count = DecompositionLevelCount(2);

    let non_native_decomposer =
        SignedDecomposerNonNative::new(base_log, level_count, ciphertext_modulus);
    let non_native_closest =
        non_native_decomposer.closest_representable(value_to_decompose_non_native);
    // 0010_1000_00...0
    assert_eq!(non_native_closest, (1u64 << 61) + (1 << 59));
    let non_native_decomp_iter = non_native_decomposer.decompose(value_to_decompose_non_native);

    // Check we get the same results shifted when computing on the shifted value to fill the MSBs
    let value_to_decompose_native = value_to_decompose_non_native << 2;
    let native_decomposer = SignedDecomposer::new(base_log, level_count);
    let native_closest = native_decomposer.closest_representable(value_to_decompose_native);
    assert_eq!(non_native_closest << 2, native_closest);

    let native_decomp_iter = native_decomposer.decompose(value_to_decompose_native);

    for (non_native_term, native_term) in non_native_decomp_iter.zip(native_decomp_iter) {
        assert_eq!(
            non_native_term.to_recomposition_summand() << 2,
            native_term.to_recomposition_summand()
        );
    }
}

fn test_decompose_recompose_non_native<T: UnsignedInteger + Debug + RandomGenerable<Uniform>>(
    ciphertext_modulus: CiphertextModulus<T>,
) where
    <T as UnsignedInteger>::Signed: Debug + SignedInteger,
{
    let ciphertext_modulus_as_t = T::cast_from(ciphertext_modulus.get_custom_modulus());
    // Checks that the decomposing and recomposing a value brings the closest representable
    for _ in 0..100_000 {
        let decomposer = random_decomp_non_native::<T>(ciphertext_modulus);
        let input = any_uint::<T>() % ciphertext_modulus_as_t;
        for term in decomposer.decompose(input) {
            assert!(1 <= term.level().0);
            assert!(term.level().0 <= decomposer.level_count);
            let term = term.value();
            let half_basis = (T::ONE << decomposer.base_log) / T::TWO;

            let abs_term = if term > ciphertext_modulus_as_t / T::TWO {
                ciphertext_modulus_as_t - term
            } else {
                term
            };

            assert!(abs_term <= half_basis);
        }
        let closest = decomposer.closest_representable(input);
        let distance = torus_abs_diff_custom_mod(input, closest, ciphertext_modulus_as_t);
        let distance_f64: f64 = distance.cast_into();
        let base_log = decomposer.base_log().0;
        let level_count = decomposer.level_count().0;
        // -1 as we don't divide exactly for prime Q
        let max_correct_bits: usize = base_log * level_count - 1;
        let max_err_bits: usize = T::BITS - max_correct_bits;
        assert!(
        distance_f64.log2() <= max_err_bits as f64,
        "base_log={base_log}, level_count={level_count}, input={input:064b}, closest={closest:064b}"
    );
    }
}

#[test]
pub fn test_decompose_recompose_non_native_u64() {
    test_decompose_recompose_non_native::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    )
}
