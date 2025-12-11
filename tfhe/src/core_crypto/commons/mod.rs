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
pub mod plan;
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

    /// Samples must come from a gaussian distribution, returns the estimated confidence interval
    /// for a mean measurement of a gaussian distribution.
    pub fn gaussian_mean_confidence_interval(
        sample_count: f64,
        measured_mean: f64,
        measured_std_dev: StandardDev,
        probability_to_be_in_the_interval: f64,
    ) -> MeanConfidenceInterval {
        assert!(probability_to_be_in_the_interval >= 0.0);
        assert!(probability_to_be_in_the_interval <= 1.0);

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

    /// Return a MeanConfidenceInterval for a measured pfail where we have a single measurement of
    /// the pfail and no standard deviation estimation.
    ///
    /// See (Wikipedia)[https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Clopper%E2%80%93Pearson_interval]
    pub fn pfail_clopper_pearson_exact_confidence_interval(
        sample_count: f64,
        measured_fails: f64,
        confidence_level: f64,
    ) -> MeanConfidenceInterval {
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

    /// Samples must come from a gaussian distribution, returns the estimated confidence interval
    /// for a variance measurement of a gaussian distribution.
    #[track_caller]
    pub fn gaussian_variance_confidence_interval(
        sample_count: f64,
        measured_variance: Variance,
        probability_to_be_in_the_interval: f64,
    ) -> VarianceConfidenceInterval {
        assert!(probability_to_be_in_the_interval >= 0.0);
        assert!(probability_to_be_in_the_interval <= 1.0);

        let alpha = 1.0 - probability_to_be_in_the_interval;
        let degrees_of_freedom = sample_count - 1.0;
        let chi2 = ChiSquared::new(degrees_of_freedom).unwrap();
        let chi2_lower = chi2.inverse_cdf(alpha / 2.0);
        let chi2_upper = chi2.inverse_cdf(1.0 - alpha / 2.0);

        let result_ok = chi2_lower.is_finite() && chi2_upper.is_finite();

        assert!(
            result_ok,
            "Got an invalid value as a result of Chi2 inverse CDF with: \n\
            sample_count={sample_count} \n\
            probability_to_be_in_the_interval={probability_to_be_in_the_interval} \n\
            this is a known issue with statrs, \
            try to change your number of samples to get a computable value."
        );

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

    /// Based on the observation that changing the number of bits allocated for the message during
    /// computations for a given noise level changes the pfail.
    ///
    /// pfail = erfc((x - µ) / (sqrt(2) * sigma))
    ///
    /// For us µ = 0 (centered gaussian for the noise)
    ///
    /// x == noise bound linked to the precision
    ///
    /// x / sigma is called standard score or z score
    ///
    /// so pfail = erfc(z / sqrt(2))
    /// and therefore z = sqrt(2) * erfcinv(pfail)
    ///
    /// for an original number of bits:
    /// pfail_orig = erfc(z_orig / sqrt(2))
    ///
    /// we have x_orig = noise_bound_orig = 1 / 2^{2 + msg_bits_orig}
    /// 1 bit of padding, some msg bits and the bit required to be 0 for correct decryption
    ///
    /// we have x_new = noise_bound_new = 1 / 2^{2 + msg_bits_new}
    /// let msg_bits_diff = msg_bits_new - msg_bits_orig
    /// we have
    ///
    /// x_new = 1 / 2^{2 + msg_bits_new}
    /// x_new = 1 / 2^{2 + msg_bits_new - msg_bits_orig + msg_bits_orig}
    /// x_new = 1 / 2^{msg_bits_diff} * 1 / 2^{2 + msg_bits_orig} = 1 / 2^{msg_bits_diff} * x_orig
    /// so z_new = z_original / 2^{msg_bits_diff}
    ///
    /// we have also:
    /// pfail_new = erfc(z_new / sqrt(2))
    ///
    /// allowing to compute the equivalent pfail knowing the number of bits in both cases and the
    /// original pfail which allows to compute the original z_score.
    pub fn equivalent_pfail_gaussian_noise(
        original_precision_with_padding: u32,
        original_pfail: f64,
        new_precision_with_padding: u32,
    ) -> f64 {
        // Both include the padding bit, the message bits and an extra bit which must not be touched
        // by the noise to properly decrypt
        let original_noise_free_bits_for_correctness = original_precision_with_padding as f64 + 1.0;
        let new_noise_free_bits_for_correctness = new_precision_with_padding as f64 + 1.0;

        let z_original_pfail =
            core::f64::consts::SQRT_2 * statrs::function::erf::erfc_inv(original_pfail);

        let noise_free_bits_diff =
            new_noise_free_bits_for_correctness - original_noise_free_bits_for_correctness;

        let z_new_pfail = z_original_pfail / 2.0f64.powf(noise_free_bits_diff);

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
        for x in coeffs.iter_mut() {
            *x /= m_norm;
        }
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
                for x in samples.iter_mut() {
                    *x = normal.sample(&mut rng)
                }
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
                for x in samples.iter_mut() {
                    *x = rng.gen();
                }
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
        // What is the pfail when having 5 bits of precision (including padding) and an original
        // pfail of 2^-64 and switching to 7 bits of precision (including padding)
        assert_eq!(
            equivalent_pfail_gaussian_noise(5, 2.0f64.powi(-128), 7),
            0.0010485821554304582
        );
    }

    #[test]
    fn test_confidence_interval() {
        // https://stats.libretexts.org/Bookshelves/Introductory_Statistics/
        // Inferential_Statistics_and_Probability_-_A_Holistic_Approach_(Geraghty)/
        // 09%3A_Point_Estimation_and_Confidence_Intervals/9.03%3A_Confidence_Intervals

        // In performance measurement of investments, standard deviation is a measure of volatility
        // or risk. Twenty monthly returns from a mutual fund show an average monthly return of
        // 1 percent and a sample standard deviation of 5 percent.
        // Find a 95% confidence interval for the monthly standard deviation of the mutual fund.

        // The Chi‐square distribution will have 20‐1 =19 degrees of freedom. Using technology,
        // we find that the two critical values are  chi2_left=8.90655
        // and   chi2_right=32.8523
        // Formula for confidence interval for sigma
        // is:  sqrt(19 * 5^2 / 32.8523) sqrt(19 * 5^2 / 8.90655) = (3.8,7.3)

        // One can say with 95% confidence that the standard deviation for this mutual fund is
        // between 3.8 and 7.3 percent per month.

        let measured_std_dev = StandardDev(0.05);
        let measured_variance = measured_std_dev.get_variance();

        let confidence_level = 0.95;

        let confidence_interval =
            gaussian_variance_confidence_interval(20., measured_variance, confidence_level);

        let lower_bound = confidence_interval.lower_bound();
        let upper_bound = confidence_interval.upper_bound();

        let approx_expected_lower_bound = StandardDev(0.038).get_variance();
        let approx_expected_upper_bound = StandardDev(0.073).get_variance();

        let lower_bound_abs_diff = (lower_bound.0 - approx_expected_lower_bound.0).abs();
        let upper_bound_abs_diff = (upper_bound.0 - approx_expected_upper_bound.0).abs();

        assert!(lower_bound_abs_diff / approx_expected_lower_bound.0 < 0.01);
        assert!(upper_bound_abs_diff / approx_expected_upper_bound.0 < 0.01);
    }
}
