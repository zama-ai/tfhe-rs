use crate::core_crypto::algorithms::misc::check_clear_content_respects_mod;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable, TUniform, Uniform};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::{CastFrom, CastInto, UnsignedInteger};
use crate::core_crypto::commons::test_tools::*;

fn test_normal_random_three_sigma<T: UnsignedTorus>() {
    //! test if the normal random generation with std_dev is below 3*std_dev (99.7%)

    // settings
    let std_dev: f64 = f64::powi(2., -20);
    let mean: f64 = 0.;
    let k = 1_000_000;
    let mut generator = new_random_generator();

    // generate normal random
    let mut samples_int = vec![T::ZERO; k];
    generator.fill_slice_with_random_gaussian(&mut samples_int, mean, std_dev);

    // converts into float
    let mut samples_float = vec![0f64; k];
    samples_float
        .iter_mut()
        .zip(samples_int.iter())
        .for_each(|(out, &elt)| *out = elt.into_torus());
    for x in samples_float.iter_mut() {
        // The upper half of the torus corresponds to the negative domain when mapping unsigned
        // integer back to float (MSB or sign bit is set)
        if *x > 0.5 {
            *x -= 1.;
        }
    }

    // tests if over 3*std_dev
    let mut number_of_samples_outside_confidence_interval: usize = 0;
    for s in samples_float.iter() {
        if *s > 3. * std_dev || *s < -3. * std_dev {
            number_of_samples_outside_confidence_interval += 1;
        }
    }

    // computes the percentage of samples over 3*std_dev
    let proportion_of_samples_outside_confidence_interval: f64 =
        (number_of_samples_outside_confidence_interval as f64) / (k as f64);

    // test
    assert!(
        proportion_of_samples_outside_confidence_interval < 0.003,
        "test normal random : proportion = {proportion_of_samples_outside_confidence_interval} ; \
        n = {number_of_samples_outside_confidence_interval}"
    );
}

#[test]
fn test_normal_random_three_sigma_u32() {
    test_normal_random_three_sigma::<u32>();
}

#[test]
fn test_normal_random_three_sigma_u64() {
    test_normal_random_three_sigma::<u64>();
}

#[test]
fn test_normal_random_f64() {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![0.0f64; SAMPLES_PER_RUN];

            rng.fill_slice_with_random_gaussian(&mut samples, 0.0, 1.0);

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

fn test_normal_random_native<Scalar: UnsignedTorus>() {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.fill_slice_with_random_gaussian(&mut samples, 0.0, f64::powi(2., -20));

            assert!(check_clear_content_respects_mod(
                &samples,
                CiphertextModulus::new_native()
            ));

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = x.into_torus();
                    // The upper half of the torus corresponds to the negative domain when mapping
                    // unsigned integer back to float (MSB or sign bit is set)
                    if torus > 0.5 {
                        torus - 1.0
                    } else {
                        torus
                    }
                })
                .collect();

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
fn test_normal_random_native_u32() {
    test_normal_random_native::<u32>();
}

#[test]
fn test_normal_random_native_u64() {
    test_normal_random_native::<u64>();
}

#[test]
fn test_normal_random_native_u128() {
    test_normal_random_native::<u128>();
}

fn test_normal_random_custom_mod<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.fill_slice_with_random_gaussian_custom_mod(
                &mut samples,
                0.0,
                f64::powi(2., -20),
                ciphertext_modulus,
            );

            assert!(check_clear_content_respects_mod(
                &samples,
                ciphertext_modulus
            ));

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = if ciphertext_modulus.is_native_modulus() {
                        x.into_torus()
                    } else {
                        x.into_torus_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
                    };
                    // The upper half of the torus corresponds to the negative domain when mapping
                    // unsigned integer back to float (MSB or sign bit is set)
                    if torus > 0.5 {
                        torus - 1.0
                    } else {
                        torus
                    }
                })
                .collect();

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
fn test_normal_random_custom_mod_u32() {
    test_normal_random_custom_mod::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn test_normal_random_custom_mod_u64() {
    test_normal_random_custom_mod::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}

#[test]
fn test_normal_random_custom_mod_u128() {
    test_normal_random_custom_mod::<u128>(CiphertextModulus::try_new_power_of_2(127).unwrap());
}

#[test]
fn test_normal_random_native_mod_u32() {
    test_normal_random_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_native_mod_u64() {
    test_normal_random_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_native_mod_u128() {
    test_normal_random_custom_mod::<u128>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_solinas_custom_mod_u64() {
    test_normal_random_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

fn test_normal_random_add_assign_native<Scalar: UnsignedTorus>() {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.unsigned_torus_slice_wrapping_add_random_gaussian_assign(
                &mut samples,
                0.0,
                f64::powi(2., -20),
            );

            assert!(check_clear_content_respects_mod(
                &samples,
                CiphertextModulus::new_native()
            ));

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = x.into_torus();
                    // The upper half of the torus corresponds to the negative domain when mapping
                    // unsigned integer back to float (MSB or sign bit is set)
                    if torus > 0.5 {
                        torus - 1.0
                    } else {
                        torus
                    }
                })
                .collect();

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
fn test_normal_random_add_assign_native_u32() {
    test_normal_random_add_assign_native::<u32>();
}

#[test]
fn test_normal_random_add_assign_native_u64() {
    test_normal_random_add_assign_native::<u64>();
}

#[test]
fn test_normal_random_add_assign_native_u128() {
    test_normal_random_add_assign_native::<u128>();
}

fn test_normal_random_add_assign_custom_mod<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.unsigned_torus_slice_wrapping_add_random_gaussian_custom_mod_assign(
                &mut samples,
                0.0,
                f64::powi(2., -20),
                ciphertext_modulus,
            );

            assert!(check_clear_content_respects_mod(
                &samples,
                ciphertext_modulus
            ));

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = if ciphertext_modulus.is_native_modulus() {
                        x.into_torus()
                    } else {
                        x.into_torus_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
                    };
                    // The upper half of the torus corresponds to the negative domain when mapping
                    // unsigned integer back to float (MSB or sign bit is set)
                    if torus > 0.5 {
                        torus - 1.0
                    } else {
                        torus
                    }
                })
                .collect();

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
fn test_normal_random_add_assign_custom_mod_u32() {
    test_normal_random_add_assign_custom_mod::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_normal_random_add_assign_custom_mod_u64() {
    test_normal_random_add_assign_custom_mod::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}

#[test]
fn test_normal_random_add_assign_custom_mod_u128() {
    test_normal_random_add_assign_custom_mod::<u128>(
        CiphertextModulus::try_new_power_of_2(127).unwrap(),
    );
}

#[test]
fn test_normal_random_add_assign_native_mod_u32() {
    test_normal_random_add_assign_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_native_mod_u64() {
    test_normal_random_add_assign_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_native_mod_u128() {
    test_normal_random_add_assign_custom_mod::<u128>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_solinas_custom_mod_u64() {
    test_normal_random_add_assign_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

pub trait DistributionTestHelper<Scalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>> {
    type CreationInfos;

    fn new_with_custom_modulus(
        value: Self::CreationInfos,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self;

    fn distinct_values(&self, ciphertext_modulus: CiphertextModulus<Scalar>) -> usize;

    fn map_usize_to_value(
        &self,
        input: usize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar;

    fn map_value_to_usize(
        &self,
        input: Scalar,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> usize;

    fn cumulative_distribution_function(
        &self,
        integer_value: Scalar,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> f64;
}

fn dkw_cdf_bands_width(number_of_samples: usize, confidence_interval: f64) -> f64 {
    // https://en.wikipedia.org/wiki/Dvoretzky%E2%80%93Kiefer%E2%80%93Wolfowitz_inequality#Building_CDF_bands
    // the true CDF is between the empirical CDF +/- this band width with probability 1 - alpha
    // Said otherwise, the abs diff should be less than that value with high probability
    fn dkw_cdf_bands_width_formula(sample_size: f64, alpha: f64) -> f64 {
        f64::sqrt(f64::ln(2.0 / alpha) / (2.0 * sample_size))
    }

    // alpha = 1 - probability of being in the interval
    dkw_cdf_bands_width_formula(number_of_samples as f64, 1.0 - confidence_interval)
}

fn test_random_from_distribution_custom_mod<Scalar, D>(
    creation_infos: D::CreationInfos,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    D: Distribution + DistributionTestHelper<Scalar>,
    Scalar: UnsignedInteger
        + CastInto<usize>
        + CastFrom<usize>
        + RandomGenerable<D, CustomModulus = Scalar>
        + std::hash::Hash,
{
    assert!(
        Scalar::BITS <= usize::BITS as usize,
        "This test cannot be run for integers with more than {} bits",
        usize::BITS
    );

    let distribution = D::new_with_custom_modulus(creation_infos, ciphertext_modulus);
    let distinct_values = distribution.distinct_values(ciphertext_modulus);

    // About 105 seconds on a dev laptop for the non native u64 case
    pub const RUNS: usize = 5000;
    // We hope to have exactly 1000 samples per value possible given the input ciphertext modulus
    pub const NUMBER_OF_SAMPLES_PER_VALUE: usize = 1000;
    pub const CONFIDENCE_INTERVAL: f64 = 0.95;
    // Expected OK rate is 0.05, we have a small tolerance as randomness is hard
    pub const EXPECTED_NOK_RATE_WITH_TOLERANCE: f64 = 0.065;

    let mut runs_nok: usize = 0;

    for _ in 0..RUNS {
        let mut bins = vec![0u64; distinct_values];
        let mut rng = new_random_generator();

        // We could do a single loop, but in the case very large sampling ever becomes possible,
        // this avoids overflowing the usize
        for _ in 0..NUMBER_OF_SAMPLES_PER_VALUE {
            for _ in 0..distinct_values {
                let random_value =
                    rng.random_from_distribution_custom_mod(distribution, ciphertext_modulus);
                let random_value_idx =
                    distribution.map_value_to_usize(random_value, ciphertext_modulus);

                bins[random_value_idx] += 1;
            }
        }

        let mut cumulative_sums = vec![0u64; distinct_values];

        let mut curr_sum = 0;

        // Compute the cumulative sums
        for (bin_count, cum_sum) in bins.iter().zip(cumulative_sums.iter_mut()) {
            curr_sum += bin_count;
            *cum_sum = curr_sum;
        }

        // Inaccurate if modulus >~ 2^53 / number_of_samples_per_bin, but if that's the case your
        // memory most likely blew up before (or the universe died its heat death)
        let number_of_samples = NUMBER_OF_SAMPLES_PER_VALUE * distinct_values;

        let sup_diff: f64 = cumulative_sums
            .iter()
            .copied()
            .enumerate()
            .map(|(bin_idx, x)| {
                // Compute the observed CDF
                let empirical_cdf = x as f64 / number_of_samples as f64;

                let integer_value: Scalar =
                    distribution.map_usize_to_value(bin_idx, ciphertext_modulus);
                // CDF for the uniform distribution
                let theoretical_cdf = distribution
                    .cumulative_distribution_function(integer_value, ciphertext_modulus);

                if theoretical_cdf == 1.0 {
                    assert_eq!(empirical_cdf, 1.0);
                }

                let diff = empirical_cdf - theoretical_cdf;
                diff.abs()
            })
            .max_by(f64::total_cmp)
            .unwrap();

        let upper_bound_for_cdf_abs_diff =
            dkw_cdf_bands_width(number_of_samples, CONFIDENCE_INTERVAL);
        let distribution_ok = sup_diff <= upper_bound_for_cdf_abs_diff;

        if !distribution_ok {
            runs_nok += 1;
        }
    }

    // 95% confidence interval means 5% of runs may end up out of that value, have a small tolerance
    let nok_ratio = runs_nok as f64 / RUNS as f64;
    assert!(
        nok_ratio <= EXPECTED_NOK_RATE_WITH_TOLERANCE,
        "nok_ratio={nok_ratio}"
    );
}

impl<Scalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>> DistributionTestHelper<Scalar>
    for Uniform
{
    type CreationInfos = ();

    fn new_with_custom_modulus(
        _value: Self::CreationInfos,
        _ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self
    }

    fn distinct_values(&self, ciphertext_modulus: CiphertextModulus<Scalar>) -> usize {
        let distinct_values: usize = if ciphertext_modulus.is_native_modulus() {
            assert!(
                Scalar::BITS <= usize::BITS as usize,
                "Unable to run test for such a large modulus {ciphertext_modulus:?}, usize::MAX {}",
                usize::MAX
            );
            1 << Scalar::BITS
        } else {
            ciphertext_modulus.get_custom_modulus().cast_into()
        };

        distinct_values
    }

    fn cumulative_distribution_function(
        &self,
        integer_value: Scalar,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> f64 {
        // This is only valid if the smallest integer value for uniform is 0 which is currently the
        // case
        let value_as_usize = self.map_value_to_usize(integer_value, ciphertext_modulus);
        let integer_f64 = (value_as_usize + 1) as f64;
        let distinct_values_f64: f64 = self.distinct_values(ciphertext_modulus) as f64;

        integer_f64 / distinct_values_f64
    }

    fn map_usize_to_value(
        &self,
        input: usize,
        _ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar {
        Scalar::cast_from(input)
    }

    fn map_value_to_usize(
        &self,
        input: Scalar,
        _ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> usize {
        input.cast_into()
    }
}

// This test takes care of all bigger native types, as underneath the CSPRNG outputs bytes
#[test]
fn test_uniform_random_native_mod_u8() {
    let ciphertext_modulus = CiphertextModulus::new_native();
    test_random_from_distribution_custom_mod::<u8, Uniform>((), ciphertext_modulus);
}

#[test]
fn test_uniform_random_custom_mod_u64() {
    // Have a modulus that will generate some rejection but is relatively small to be able to test
    // quickly
    let ciphertext_modulus = CiphertextModulus::try_new((1 << 10) + (1 << 9)).unwrap();
    test_random_from_distribution_custom_mod::<u64, Uniform>((), ciphertext_modulus);
}

impl<Scalar: UnsignedInteger + CastFrom<usize> + CastInto<usize>> DistributionTestHelper<Scalar>
    for TUniform<Scalar>
{
    type CreationInfos = u32;

    fn new_with_custom_modulus(
        value: Self::CreationInfos,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(ciphertext_modulus.is_native_modulus());
        Self::new(value)
    }

    fn distinct_values(&self, _ciphertext_modulus: CiphertextModulus<Scalar>) -> usize {
        // TUniform does not support non native moduli for now
        self.distinct_value_count()
    }

    fn cumulative_distribution_function(
        &self,
        integer_value: Scalar,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> f64 {
        let max_value_inclusive = self.max_value_inclusive();
        let integer_value_signed: Scalar::Signed = integer_value.cast_into();
        let value_index: usize = self.map_value_to_usize(integer_value, ciphertext_modulus);
        // CDF for the TUniform distribution
        if integer_value_signed == max_value_inclusive {
            1.0
        } else {
            2.0f64.powi(-(self.bound_log2() as i32 + 2))
                + 2.0f64.powi(-(self.bound_log2() as i32 + 1)) * value_index as f64
        }
    }

    fn map_usize_to_value(
        &self,
        input: usize,
        _ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Scalar {
        // Input is in [0; 2^(b + 1)]
        let input_as_scalar = Scalar::cast_from(input);
        // Cast to signed
        let input_as_signed_scalar: Scalar::Signed = input_as_scalar.cast_into();
        let min_value_inclusive = self.min_value_inclusive();
        // This is in [-2^b; 2^b]
        let value_as_signed = input_as_signed_scalar + min_value_inclusive;
        Scalar::cast_from(value_as_signed)
    }

    fn map_value_to_usize(
        &self,
        input: Scalar,
        _ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> usize {
        // Input is in [-2^b; 2^b]
        let input_as_signed_scalar: Scalar::Signed = input.cast_into();
        let min_value_inclusive = self.min_value_inclusive();
        // This is in [0; 2^(b + 1)]
        let index_as_signed = input_as_signed_scalar - min_value_inclusive;
        // Re-cast to unsigned otherwise traits are annoying to deal with
        let index_as_scalar = Scalar::cast_from(index_as_signed);
        // Cast to usize to finish
        index_as_scalar.cast_into()
    }
}

#[test]
fn test_t_uniform_random_u64() {
    // Means the random will be in [-2048; 2048]
    let bound_log2 = 11u32;
    let ciphertext_modulus = CiphertextModulus::new_native();
    test_random_from_distribution_custom_mod::<u64, TUniform<_>>(bound_log2, ciphertext_modulus);
}

#[test]
fn test_uniform_sample_success_probability() {
    {
        let modulus = ((1u128 << 64) - (1 << 32) + 1) as u64;
        let generation_success_rate =
            <u64 as RandomGenerable<Uniform>>::single_sample_success_probability(
                Uniform,
                Some(modulus),
            );

        assert_eq!(generation_success_rate, modulus as f64 / 2.0f64.powi(64));
    }

    {
        // None = native modulus
        let generation_success_rate =
            <u64 as RandomGenerable<Uniform>>::single_sample_success_probability(Uniform, None);

        assert_eq!(generation_success_rate, 1.0);
    }
}
