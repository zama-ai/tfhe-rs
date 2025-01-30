pub mod atomic_pattern;

use crate::core_crypto::commons::dispersion::Variance;

/// Return the [`Variance`] if a [`Ciphertext`](`crate::shortint::Ciphertext`) with input variance
/// `input_variance` is multiplied by the provided `scalar`.
pub fn scalar_multiplication_variance(input_variance: Variance, scalar: u64) -> Variance {
    let multiplicative_factor = scalar.checked_pow(2).unwrap();
    Variance(input_variance.0 * multiplicative_factor as f64)
}

pub fn should_use_one_key_per_sample() -> bool {
    static ONE_KEY_PER_SAMPLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    *ONE_KEY_PER_SAMPLE.get_or_init(|| {
        std::env::var("NOISE_MEASUREMENT_USE_PER_SAMPLE_KEY").is_ok_and(|val| {
            let val = val.parse::<u32>();
            val.is_ok_and(|val| val != 0)
        })
    })
}

pub fn should_run_long_pfail_tests() -> bool {
    static LONG_PFAIL_TESTS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    *LONG_PFAIL_TESTS.get_or_init(|| {
        std::env::var("NOISE_MEASUREMENT_LONG_PFAIL_TESTS").is_ok_and(|val| {
            let val = val.parse::<u32>();
            val.is_ok_and(|val| val != 0)
        })
    })
}
