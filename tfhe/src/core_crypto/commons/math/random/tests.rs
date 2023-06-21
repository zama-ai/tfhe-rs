use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::torus::{CastInto, UnsignedTorus};
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
fn test_normal_random_native_custom_mod_u32() {
    test_normal_random_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_native_custom_mod_u64() {
    test_normal_random_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_native_custom_mod_u128() {
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
fn test_normal_random_add_assign_native_custom_mod_u32() {
    test_normal_random_add_assign_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_native_custom_mod_u64() {
    test_normal_random_add_assign_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_native_custom_mod_u128() {
    test_normal_random_add_assign_custom_mod::<u128>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_add_assign_solinas_custom_mod_u64() {
    test_normal_random_add_assign_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}
