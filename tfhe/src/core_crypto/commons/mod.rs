//! Module containing common mathematical objects/cryptographic primitives like random generators or
//! traits expected to be re-used in various algorithms and entities implementations.
//!
//! # Dispersion
//! This module contains the functions used to compute the variance, standard
//! deviation, etc.
//!
//! # Parameters
//! This module contains structures that wrap unsigned integer parameters like the ciphertext
//! dimension or the polynomial degree.

pub mod ciphertext_modulus;
pub mod computation_buffers;
pub mod dispersion;
pub mod generators;
pub mod math;
pub mod noise_formulas;
pub mod numeric;
pub mod parameters;
pub mod utils;

// Refactor modules
pub mod traits;

#[doc(hidden)]
#[cfg(test)]
pub mod test_tools {
    use rand::Rng;
    use statrs::distribution::{ChiSquared, ContinuousCDF, Normal};

    pub use crate::core_crypto::algorithms::misc::{
        modular_distance, modular_distance_custom_mod, torus_modular_diff,
    };
    use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
    use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev, Variance};
    use crate::core_crypto::commons::generators::{
        EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::core_crypto::commons::math::random::{
        DefaultRandomGenerator, RandomGenerable, RandomGenerator, Uniform,
    };
    use crate::core_crypto::commons::parameters::{
        CiphertextCount, DecompositionBaseLog, DecompositionLevelCount, GlweDimension,
        LweDimension, PlaintextCount, PolynomialSize,
    };
    use crate::core_crypto::commons::traits::*;
    use tfhe_csprng::seeders::Seed;

    pub fn check_both_ratio_under(a: f64, b: f64, max_ratio: f64) -> bool {
        assert!(a > 0.0 && b > 0.0);
        a / b < max_ratio && b / a < max_ratio
    }

    pub fn arithmetic_mean(samples: &[f64]) -> f64 {
        let sample_count = samples.len();

        samples.iter().sum::<f64>() / (sample_count as f64)
    }

    #[derive(Debug, Clone, Copy)]
    pub struct MeanConfidenceInterval {
        lower_bound: f64,
        upper_bound: f64,
    }

    impl MeanConfidenceInterval {
        pub fn mean_is_in_interval(&self, mean_to_check: f64) -> bool {
            self.lower_bound <= mean_to_check && self.upper_bound >= mean_to_check
        }

        pub fn lower_bound(&self) -> f64 {
            self.lower_bound
        }

        pub fn upper_bound(&self) -> f64 {
            self.upper_bound
        }
    }

    pub fn mean_confidence_interval(
        sample_count: f64,
        measured_mean: f64,
        measured_std_dev: StandardDev,
        probability_to_be_in_the_interval: f64,
    ) -> MeanConfidenceInterval {
        let standard_score = core::f64::consts::SQRT_2
            * statrs::function::erf::erfc_inv(1.0 - probability_to_be_in_the_interval);
        let interval_delta = standard_score * measured_std_dev.0 / f64::sqrt(sample_count);

        let lower_bound = measured_mean - interval_delta;
        let upper_bound = measured_mean + interval_delta;

        assert!(lower_bound <= upper_bound);

        MeanConfidenceInterval {
            lower_bound,
            upper_bound,
        }
    }

    /// Return a MeanConfidenceInterval when you cannot evaluate the standard deviation of a random
    /// variable
    pub fn clopper_pearson_exact_confidence_interval(
        sample_count: f64,
        measured_fails: f64,
        confidence_level: f64,
    ) -> MeanConfidenceInterval {
        // import scipy.stats as stats
        // import math
        //
        // # Parameters
        // n_tests = 10000  # Number of trials
        // p_fail = 2**-5.5  # Theoretical probability of failure
        // alpha = 0.01  # Significance level (1 - confidence level)
        //
        // # /!\ to be replaced by the experimental number of failures
        // observed_failures = round(n_tests * p_fail)
        //
        // # Clopper-Pearson Exact Confidence Interval
        // lower_bound = stats.beta.ppf(alpha / 2, observed_failures, n_tests - observed_failures +
        // 1) upper_bound = stats.beta.ppf(1 - alpha / 2, observed_failures + 1, n_tests -
        // observed_failures)
        //
        // print("Observed number of failures (k):", observed_failures)
        // print(f"Confidence Interval ({(1-alpha)*100}%): [2^{round(math.log2(lower_bound),3)},
        // 2^{round(math.log2(upper_bound),3)}]")

        let alpha = 1.0 - confidence_level;
        let beta_distribution_lower_bound =
            statrs::distribution::Beta::new(measured_fails, sample_count - measured_fails + 1.0)
                .unwrap();
        let beta_distribution_upper_bound =
            statrs::distribution::Beta::new(measured_fails + 1.0, sample_count - measured_fails)
                .unwrap();

        let lower_bound = beta_distribution_lower_bound.inverse_cdf(alpha / 2.0);
        let upper_bound = beta_distribution_upper_bound.inverse_cdf(1.0 - alpha / 2.0);

        assert!(lower_bound <= upper_bound);

        MeanConfidenceInterval {
            lower_bound,
            upper_bound,
        }
    }

    pub fn variance(samples: &[f64]) -> Variance {
        let sample_count = samples.len();

        let mean = arithmetic_mean(samples);

        let sum_squared_deviations_to_the_mean =
            samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>();

        Variance(sum_squared_deviations_to_the_mean / ((sample_count - 1) as f64))
    }

    #[derive(Debug, Clone, Copy)]
    pub struct VarianceConfidenceInterval {
        lower_bound: Variance,
        upper_bound: Variance,
    }

    impl VarianceConfidenceInterval {
        pub fn variance_is_in_interval(&self, variance_to_check: Variance) -> bool {
            self.lower_bound <= variance_to_check && self.upper_bound >= variance_to_check
        }

        pub fn lower_bound(&self) -> Variance {
            self.lower_bound
        }

        pub fn upper_bound(&self) -> Variance {
            self.upper_bound
        }
    }

    pub fn variance_confidence_interval(
        sample_count: f64,
        measured_variance: Variance,
        probability_to_be_in_the_interval: f64,
    ) -> VarianceConfidenceInterval {
        assert!(probability_to_be_in_the_interval >= 0.0);
        assert!(probability_to_be_in_the_interval <= 1.0);

        assert!(
            sample_count <= 775030.,
            "variance_confidence_interval cannot handle sample count > 775030",
        );

        let alpha = 1.0 - probability_to_be_in_the_interval;
        let degrees_of_freedom = sample_count - 1.0;
        let chi2 = ChiSquared::new(degrees_of_freedom).unwrap();
        let chi2_lower = chi2.inverse_cdf(alpha / 2.0);
        let chi2_upper = chi2.inverse_cdf(1.0 - alpha / 2.0);

        // Lower bound is divided by Chi_right^2 so by chi2_upper, upper bound divided by Chi_left^2
        // so chi2_lower
        let lower_bound = Variance(degrees_of_freedom * measured_variance.0 / chi2_upper);
        let upper_bound = Variance(degrees_of_freedom * measured_variance.0 / chi2_lower);

        assert!(
            lower_bound <= upper_bound,
            "Lower bound is {lower_bound:?}, upper bound is {upper_bound:?}\
            This is inconsistent aborting"
        );

        VarianceConfidenceInterval {
            lower_bound,
            upper_bound,
        }
    }

    pub fn new_random_generator() -> RandomGenerator<DefaultRandomGenerator> {
        RandomGenerator::new(random_seed())
    }

    pub fn new_secret_random_generator() -> SecretRandomGenerator<DefaultRandomGenerator> {
        SecretRandomGenerator::new(random_seed())
    }

    pub fn new_encryption_random_generator() -> EncryptionRandomGenerator<DefaultRandomGenerator> {
        EncryptionRandomGenerator::new(random_seed(), &mut UnsafeRandSeeder)
    }

    pub fn random_seed() -> Seed {
        Seed(rand::thread_rng().gen())
    }

    pub struct UnsafeRandSeeder;

    impl Seeder for UnsafeRandSeeder {
        fn seed(&mut self) -> Seed {
            Seed(rand::thread_rng().gen())
        }

        fn is_available() -> bool {
            true
        }
    }

    pub fn assert_delta_std_dev<First, Second, Element>(
        first: &First,
        second: &Second,
        dist: impl DispersionParameter,
    ) where
        First: Container<Element = Element>,
        Second: Container<Element = Element>,
        Element: UnsignedTorus,
    {
        for (x, y) in first.as_ref().iter().zip(second.as_ref().iter()) {
            println!("{:?}, {:?}", *x, *y);
            println!("{:?}", dist.get_standard_dev());
            let distance: f64 = modular_distance(*x, *y).cast_into();
            let torus_distance = distance / 2_f64.powi(Element::BITS as i32);
            assert!(
                torus_distance <= 5. * dist.get_standard_dev().0,
                "{x} != {y} "
            );
        }
    }

    pub struct NormalityTestResult {
        pub w_prime: f64,
        pub p_value: f64,
        pub null_hypothesis_is_valid: bool,
    }

    pub fn equivalent_pfail_gaussian_noise(
        original_precision_with_padding: u32,
        original_pfail: f64,
        new_precision_with_padding: u32,
    ) -> f64 {
        let original_precision_with_padding_and_noise_gap =
            original_precision_with_padding as f64 + 1.0;
        let new_precision_with_padding_and_noise_gap = new_precision_with_padding as f64 + 1.0;

        let z_original_pfail =
            core::f64::consts::SQRT_2 * statrs::function::erf::erfc_inv(original_pfail);

        let precision_diff = new_precision_with_padding_and_noise_gap
            - original_precision_with_padding_and_noise_gap;

        let z_new_pfail = z_original_pfail / 2.0f64.powf(precision_diff);

        statrs::function::erf::erfc(z_new_pfail / core::f64::consts::SQRT_2)
    }

    /// Normal law CDF
    fn phi(x: f64) -> f64 {
        let normal_law = Normal::new(0.0, 1.0).unwrap();
        normal_law.cdf(x)
    }

    /// (Normal law CDF)^{-1}
    fn phi_inv(x: f64) -> f64 {
        let normal_law = Normal::new(0.0, 1.0).unwrap();
        normal_law.inverse_cdf(x)
    }

    /// Based on Shapiro-Francia normality test
    pub fn normality_test_f64(samples: &[f64], alpha: f64) -> NormalityTestResult {
        assert!(
            samples.len() <= 5000,
            "normality_test_f64 produces a relevant pvalue for less than 5000 samples"
        );

        let n = samples.len();
        let n_f64 = n as f64;
        // Sort the input
        let mut samples: Vec<_> = samples.to_vec();
        samples.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let samples = samples;
        // Compute the mean
        let mean = samples.iter().copied().sum::<f64>() / n_f64;
        let frac_three_eight = 3. / 8.;
        let frac_one_four = 1. / 4.;
        // Compute Blom scores
        let m_tilde: Vec<_> = (1..=n)
            .map(|i| phi_inv((i as f64 - frac_three_eight) / (n_f64 + frac_one_four)))
            .collect();
        // Blom scores norm2
        let m_norm = f64::sqrt(m_tilde.iter().fold(0.0, |acc, x| acc + x * x));
        // Coefficients
        let mut coeffs = m_tilde;
        coeffs.iter_mut().for_each(|x| *x /= m_norm);
        // Test statistic
        let denominator = samples.iter().fold(0.0, |acc, x| acc + (x - mean).powi(2));
        let numerator = samples
            .iter()
            .zip(coeffs.iter())
            .fold(0.0, |acc, (&sample, &coeff)| acc + sample * coeff)
            .powi(2);
        let w_prime = numerator / denominator;

        let g_w_prime = f64::ln(1.0 - w_prime);
        let log_n = n_f64.ln();
        let log_log_n = log_n.ln();
        let u = log_log_n - log_n;
        let mu = 1.0521 * u - 1.2725;
        let v = log_log_n + 2.0 / log_n;
        let sigma = -0.26758 * v + 1.0308;
        let z = (g_w_prime - mu) / sigma;
        let p_value = 1.0 - phi(z);

        NormalityTestResult {
            w_prime,
            p_value,
            null_hypothesis_is_valid: p_value > alpha,
        }
    }

    /// Return a random plaintext count in [1;max].
    pub fn random_plaintext_count(max: usize) -> PlaintextCount {
        let max = std::cmp::max(2, max);
        PlaintextCount(random_usize_between(1..max + 1))
    }

    /// Return a random ciphertext count in [1;max].
    pub fn random_ciphertext_count(max: usize) -> CiphertextCount {
        let max = std::cmp::max(2, max);
        CiphertextCount(random_usize_between(1..max + 1))
    }

    /// Return a random LWE dimension in [1;max].
    pub fn random_lwe_dimension(max: usize) -> LweDimension {
        let max = std::cmp::max(2, max);
        LweDimension(random_usize_between(1..max + 1))
    }

    /// Return a random GLWE dimension in [1;max].
    pub fn random_glwe_dimension(max: usize) -> GlweDimension {
        let max = std::cmp::max(2, max);
        GlweDimension(random_usize_between(1..max + 1))
    }

    /// Return a random polynomial size in [2;max].
    pub fn random_polynomial_size(max: usize) -> PolynomialSize {
        let max = std::cmp::max(3, max);
        PolynomialSize(random_usize_between(2..max + 1))
    }

    /// Return a random base log in [2;max].
    pub fn random_base_log(max: usize) -> DecompositionBaseLog {
        let max = std::cmp::max(3, max);
        DecompositionBaseLog(random_usize_between(2..max + 1))
    }

    /// Return a random level count in [2;max].
    pub fn random_level_count(max: usize) -> DecompositionLevelCount {
        let max = std::cmp::max(3, max);
        DecompositionLevelCount(random_usize_between(2..max + 1))
    }

    pub fn random_i32_between(range: std::ops::Range<i32>) -> i32 {
        use rand::distributions::{Distribution, Uniform};
        let between = Uniform::from(range);
        let mut rng = rand::thread_rng();
        between.sample(&mut rng)
    }

    pub fn random_usize_between(range: std::ops::Range<usize>) -> usize {
        use rand::distributions::{Distribution, Uniform};
        let between = Uniform::from(range);
        let mut rng = rand::thread_rng();
        between.sample(&mut rng)
    }

    pub fn any_usize() -> usize {
        random_usize_between(0..usize::MAX)
    }

    pub fn random_uint_between<T: UnsignedInteger + RandomGenerable<Uniform>>(
        range: std::ops::Range<T>,
    ) -> T {
        let mut generator = new_random_generator();
        let val: T = generator.random_uniform();
        val % (range.end - range.start) + range.start
    }

    pub fn any_uint<T: UnsignedInteger + RandomGenerable<Uniform>>() -> T {
        let mut generator = new_random_generator();
        generator.random_uniform()
    }

    #[test]
    pub fn test_normality_tool() {
        use rand_distr::{Distribution, Normal};
        const RUNS: usize = 10000;
        const SAMPLES_PER_RUN: usize = 1000;
        let mut rng = rand::thread_rng();
        let normal = Normal::new(0.0, 1.0).unwrap();
        let failures: f64 = (0..RUNS)
            .map(|_| {
                let mut samples = vec![0.0f64; SAMPLES_PER_RUN];
                samples
                    .iter_mut()
                    .for_each(|x| *x = normal.sample(&mut rng));
                if normality_test_f64(&samples, 0.05).null_hypothesis_is_valid {
                    // If we are normal return 0, it's not a failure
                    0.0
                } else {
                    1.0
                }
            })
            .sum::<f64>();
        let failure_rate = failures / (RUNS as f64);
        println!("failure_rate: {failure_rate}");
        // The expected failure rate even on proper gaussian is 5%, so we take a small safety margin
        assert!(failure_rate <= 0.065);
    }

    #[test]
    pub fn test_normality_tool_fail_uniform() {
        const RUNS: usize = 10000;
        const SAMPLES_PER_RUN: usize = 1000;
        let mut rng = rand::thread_rng();
        let failures: f64 = (0..RUNS)
            .map(|_| {
                let mut samples = vec![0.0f64; SAMPLES_PER_RUN];
                samples.iter_mut().for_each(|x| *x = rng.gen());
                if normality_test_f64(&samples, 0.05).null_hypothesis_is_valid {
                    // If we are normal return 0, it's not a failure
                    0.0
                } else {
                    1.0
                }
            })
            .sum::<f64>();
        let failure_rate = failures / (RUNS as f64);
        assert!(failure_rate == 1.0);
    }

    #[test]
    pub fn test_torus_modular_diff() {
        {
            // q = 2^64
            let q = CiphertextModulus::<u64>::new_native();
            // Divide by 8 to get an exact division vs 10 or anything not a power of 2
            let one_eighth = ((1u128 << 64) / 8) as u64;
            let seven_eighth = 7 * one_eighth;

            let distance = torus_modular_diff(one_eighth, seven_eighth, q);
            assert_eq!(distance, 0.25);
            let distance = torus_modular_diff(seven_eighth, one_eighth, q);
            assert_eq!(distance, -0.25);
        }
        {
            // q = 2^63
            let q = CiphertextModulus::<u64>::try_new_power_of_2(63).unwrap();
            // Divide by 8 to get an exact division vs 10 or anything not a power of 2
            let one_eighth = q.get_custom_modulus() as u64 / 8;
            let seven_eighth = 7 * one_eighth;

            let distance = torus_modular_diff(one_eighth, seven_eighth, q);
            assert_eq!(distance, 0.25);
            let distance = torus_modular_diff(seven_eighth, one_eighth, q);
            assert_eq!(distance, -0.25);
        }
        {
            // q = 2^64 - 2^32 + 1
            let q = CiphertextModulus::<u64>::try_new((1 << 64) - (1 << 32) + 1).unwrap();
            // Even though 8 does not divide q exactly, everything work ok for this example.
            // This may not be the case for all moduli with enough LSBs set as then one_eighth would
            // be the floor and not the rounding of q / 8, here they happen to match and that's good
            // enough
            let one_eighth = q.get_custom_modulus() as u64 / 8;
            let seven_eighth = 7 * one_eighth;

            let distance = torus_modular_diff(one_eighth, seven_eighth, q);
            assert_eq!(distance, 0.25);
            let distance = torus_modular_diff(seven_eighth, one_eighth, q);
            assert_eq!(distance, -0.25);
        }
    }

    #[test]
    fn test_equivalent_pfail() {
        let equiv_pfail = equivalent_pfail_gaussian_noise(7, 0.001067, 5);
        println!("{equiv_pfail}");
        println!("{}", equiv_pfail.log2());

        assert_eq!(
            equivalent_pfail_gaussian_noise(5, 2.0f64.powi(-64), 7),
            0.022089612797217772
        );
    }

    #[test]
    #[allow(clippy::while_float)]
    fn chi2_limit() {
        let probability_to_be_in_the_interval = 0.99f64;
        let alpha = 1.0f64 - probability_to_be_in_the_interval;

        let mut df_low = 1.0f64;
        let mut df_high = 1000000.0f64 - 1.0;

        let mut prev_df = 0.0;

        while df_high - df_low >= 1.0 {
            let df = ((df_high + df_low) / 2.0).ceil();
            if df == prev_df {
                break;
            }

            prev_df = df;
            println!("testing df={df}");
            let chi2 = ChiSquared::new(df).unwrap();
            let chi2_lower = chi2.inverse_cdf(alpha / 2.0);
            let chi2_upper = chi2.inverse_cdf(1.0 - alpha / 2.0);

            println!("chi2_lower={chi2_lower}");
            println!("chi2_upper={chi2_upper}");
            println!("chi2_lower_log10={}", chi2_lower.log10());
            println!("chi2_upper_log10={}", chi2_upper.log10());

            if chi2_lower.is_nan()
                || chi2_lower.is_infinite()
                || chi2_upper.is_nan()
                || chi2_upper.is_infinite()
            {
                println!("Nan");
                df_high = df;
            } else {
                println!("OK");
                df_low = df;
            }
        }
    }

    #[test]
    fn chi2_gaussian_equivalency() {
        let probability_to_be_in_the_interval = 0.99f64;
        let alpha = 1.0f64 - probability_to_be_in_the_interval;

        let df = 775029f64;

        let chi2 = ChiSquared::new(df).unwrap();
        let chi2_lower = chi2.inverse_cdf(alpha / 2.0);
        let chi2_upper = chi2.inverse_cdf(1.0 - alpha / 2.0);

        let equiv_var = 2.0 * df;
        let equivalent_gaussian = statrs::distribution::Normal::new(df, equiv_var.sqrt()).unwrap();
        let norm_lower = equivalent_gaussian.inverse_cdf(alpha / 2.0);
        let norm_upper = equivalent_gaussian.inverse_cdf(1.0 - alpha / 2.0);

        println!("chi2_lower={chi2_lower}");
        println!("chi2_upper={chi2_upper}");

        println!("norm_lower={norm_lower}");
        println!("norm_upper={norm_upper}");
    }
}
