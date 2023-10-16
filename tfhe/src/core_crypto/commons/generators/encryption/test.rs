use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::{StandardDev, Variance};
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension,
    PolynomialSize,
};
use crate::core_crypto::commons::test_tools::{
    new_encryption_random_generator, new_secret_random_generator, normality_test_f64,
};
use crate::core_crypto::commons::traits::UnsignedTorus;

#[test]
fn test_gaussian_sampling_margin_factor_does_not_panic() {
    struct Params {
        glwe_size: GlweSize,
        poly_size: PolynomialSize,
        dec_level_count: DecompositionLevelCount,
        dec_base_log: DecompositionBaseLog,
        lwe_dim: LweDimension,
    }
    let params = Params {
        glwe_size: GlweSize(2),
        poly_size: PolynomialSize(1),
        dec_level_count: DecompositionLevelCount(1),
        dec_base_log: DecompositionBaseLog(4),
        lwe_dim: LweDimension(17000),
    };
    let mut enc_generator = new_encryption_random_generator();
    let mut sec_generator = new_secret_random_generator();
    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
        params.lwe_dim,
        &mut sec_generator,
    );
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        params.glwe_size.to_glwe_dimension(),
        params.poly_size,
        &mut sec_generator,
    );
    let _bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk,
        &glwe_sk,
        params.dec_base_log,
        params.dec_level_count,
        Variance(0.),
        CiphertextModulus::new_native(),
        &mut enc_generator,
    );
}

fn noise_gen_native<Scalar: UnsignedTorus>() {
    let mut gen = new_encryption_random_generator();

    let bits = (Scalar::BITS / 2) as i32;

    for _ in 0..1000 {
        let mut retries = 100;

        let mut val = Scalar::ZERO;
        while retries >= 0 {
            val = gen.random_noise(StandardDev(2.0f64.powi(-bits)));
            if val != Scalar::ZERO {
                break;
            }
            retries -= 1;
        }

        assert!(retries != 0);
        assert!(val != Scalar::ZERO);
    }
}

#[test]
fn noise_gen_native_u32() {
    noise_gen_native::<u32>();
}

#[test]
fn noise_gen_native_u64() {
    noise_gen_native::<u64>();
}

#[test]
fn noise_gen_native_u128() {
    noise_gen_native::<u128>();
}

fn noise_gen_custom_mod<Scalar: UnsignedTorus>(ciphertext_modulus: CiphertextModulus<Scalar>) {
    let mut gen = new_encryption_random_generator();

    let bits = if ciphertext_modulus.is_native_modulus() {
        Scalar::BITS as i32 / 2
    } else {
        ciphertext_modulus.get_custom_modulus().ilog2() as i32 / 2
    };

    for _ in 0..1000 {
        let mut retries = 100;

        let mut val = Scalar::ZERO;
        while retries >= 0 {
            val = gen.random_noise_custom_mod(StandardDev(2.0f64.powi(-bits)), ciphertext_modulus);
            if val != Scalar::ZERO {
                break;
            }
            retries -= 1;
        }

        assert!(retries != 0);
        assert!(val != Scalar::ZERO);
    }
}

#[test]
fn noise_gen_custom_mod_u32() {
    noise_gen_custom_mod::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn noise_gen_custom_mod_u64() {
    noise_gen_custom_mod::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}

#[test]
fn noise_gen_custom_mod_u128() {
    noise_gen_custom_mod::<u128>(CiphertextModulus::try_new_power_of_2(127).unwrap());
}

#[test]
fn noise_gen_native_custom_mod_u32() {
    noise_gen_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn noise_gen_native_custom_mod_u64() {
    noise_gen_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn noise_gen_native_custom_mod_u128() {
    noise_gen_custom_mod::<u128>(CiphertextModulus::new_native());
}

fn noise_gen_slice_native<Scalar: UnsignedTorus>() {
    let mut gen = new_encryption_random_generator();

    let bits = (Scalar::BITS / 2) as i32;

    let mut vec = vec![Scalar::ZERO; 1000];
    let mut retries = 100;
    while retries >= 0 {
        gen.fill_slice_with_random_noise(&mut vec, StandardDev(2.0f64.powi(-bits)));
        if vec.iter().all(|&x| x != Scalar::ZERO) {
            break;
        }

        retries -= 1;
    }
    assert!(retries != 0);
    assert!(vec.iter().all(|&x| x != Scalar::ZERO));
}

#[test]
fn noise_gen_slice_native_u32() {
    noise_gen_slice_native::<u32>();
}

#[test]
fn noise_gen_slice_native_u64() {
    noise_gen_slice_native::<u64>();
}

#[test]
fn noise_gen_slice_native_u128() {
    noise_gen_slice_native::<u128>();
}

fn test_normal_random_encryption_native<Scalar: UnsignedTorus>() {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_encryption_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.fill_slice_with_random_noise(&mut samples, StandardDev(f64::powi(2., -20)));

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = x.into_torus();
                    // The upper half of the torus corresponds to the negative domain when
                    // mapping unsigned integer back to float (MSB or
                    // sign bit is set)
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
fn test_normal_random_encryption_native_u32() {
    test_normal_random_encryption_native::<u32>();
}

#[test]
fn test_normal_random_encryption_native_u64() {
    test_normal_random_encryption_native::<u64>();
}

#[test]
fn test_normal_random_encryption_native_u128() {
    test_normal_random_encryption_native::<u128>();
}

fn test_normal_random_encryption_add_assign_native<Scalar: UnsignedTorus>() {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_encryption_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.unsigned_torus_slice_wrapping_add_random_noise_assign(
                &mut samples,
                StandardDev(f64::powi(2., -20)),
            );

            let samples: Vec<f64> = samples
                .iter()
                .copied()
                .map(|x| {
                    let torus = x.into_torus();
                    // The upper half of the torus corresponds to the negative domain when
                    // mapping unsigned integer back to float (MSB or
                    // sign bit is set)
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
fn test_normal_random_encryption_add_assign_native_u32() {
    test_normal_random_encryption_add_assign_native::<u32>();
}

#[test]
fn test_normal_random_encryption_add_assign_native_u64() {
    test_normal_random_encryption_add_assign_native::<u64>();
}

#[test]
fn test_normal_random_encryption_add_assign_native_u128() {
    test_normal_random_encryption_add_assign_native::<u128>();
}

fn noise_gen_slice_custom_mod<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    let mut gen = new_encryption_random_generator();

    let bits = if ciphertext_modulus.is_native_modulus() {
        Scalar::BITS as i32 / 2
    } else {
        ciphertext_modulus.get_custom_modulus().ilog2() as i32 / 2
    };

    let mut vec = vec![Scalar::ZERO; 1000];
    let mut retries = 100;
    while retries >= 0 {
        gen.fill_slice_with_random_noise_custom_mod(
            &mut vec,
            StandardDev(2.0f64.powi(-bits)),
            ciphertext_modulus,
        );
        if vec.iter().all(|&x| x != Scalar::ZERO) {
            break;
        }

        retries -= 1;
    }
    assert!(retries != 0);
    assert!(vec.iter().all(|&x| x != Scalar::ZERO));
}

#[test]
fn noise_gen_slice_custom_mod_u32() {
    noise_gen_slice_custom_mod::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn noise_gen_slice_custom_mod_u64() {
    noise_gen_slice_custom_mod::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}

#[test]
fn noise_gen_slice_custom_mod_u128() {
    noise_gen_slice_custom_mod::<u128>(CiphertextModulus::try_new_power_of_2(127).unwrap());
}

#[test]
fn noise_gen_slice_native_custom_mod_u32() {
    noise_gen_slice_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn noise_gen_slice_native_custom_mod_u64() {
    noise_gen_slice_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn noise_gen_slice_native_custom_mod_u128() {
    noise_gen_slice_custom_mod::<u128>(CiphertextModulus::new_native());
}

fn test_normal_random_encryption_custom_mod<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_encryption_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.fill_slice_with_random_noise_custom_mod(
                &mut samples,
                StandardDev(f64::powi(2., -20)),
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
                    // The upper half of the torus corresponds to the negative domain when
                    // mapping unsigned integer back to float (MSB or
                    // sign bit is set)
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
fn test_normal_random_encryption_custom_mod_u32() {
    test_normal_random_encryption_custom_mod::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_custom_mod_u64() {
    test_normal_random_encryption_custom_mod::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_custom_mod_solinas_u64() {
    test_normal_random_encryption_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_custom_mod_u128() {
    test_normal_random_encryption_custom_mod::<u128>(
        CiphertextModulus::try_new_power_of_2(127).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_native_custom_mod_u32() {
    test_normal_random_encryption_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_encryption_native_custom_mod_u64() {
    test_normal_random_encryption_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_encryption_native_custom_mod_u128() {
    test_normal_random_encryption_custom_mod::<u128>(CiphertextModulus::new_native());
}

fn test_normal_random_encryption_add_assign_custom_mod<Scalar: UnsignedTorus>(
    ciphertext_modulus: CiphertextModulus<Scalar>,
) {
    const RUNS: usize = 10000;
    const SAMPLES_PER_RUN: usize = 1000;
    let mut rng = new_encryption_random_generator();
    let failures: f64 = (0..RUNS)
        .map(|_| {
            let mut samples = vec![Scalar::ZERO; SAMPLES_PER_RUN];

            rng.unsigned_torus_slice_wrapping_add_random_noise_custom_mod_assign(
                &mut samples,
                StandardDev(f64::powi(2., -20)),
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
                    // The upper half of the torus corresponds to the negative domain when
                    // mapping unsigned integer back to float (MSB or
                    // sign bit is set)
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
fn test_normal_random_encryption_add_assign_custom_mod_u32() {
    test_normal_random_encryption_add_assign_custom_mod::<u32>(
        CiphertextModulus::try_new_power_of_2(31).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_add_assign_custom_mod_u64() {
    test_normal_random_encryption_add_assign_custom_mod::<u64>(
        CiphertextModulus::try_new_power_of_2(63).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_add_assign_custom_mod_solinas_u64() {
    test_normal_random_encryption_add_assign_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_add_assign_custom_mod_u128() {
    test_normal_random_encryption_add_assign_custom_mod::<u128>(
        CiphertextModulus::try_new_power_of_2(127).unwrap(),
    );
}

#[test]
fn test_normal_random_encryption_add_assign_native_custom_mod_u32() {
    test_normal_random_encryption_add_assign_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_encryption_add_assign_native_custom_mod_u64() {
    test_normal_random_encryption_add_assign_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn test_normal_random_encryption_add_assign_native_custom_mod_u128() {
    test_normal_random_encryption_add_assign_custom_mod::<u128>(CiphertextModulus::new_native());
}

fn mask_gen_slice_native<Scalar: UnsignedTorus>() {
    let mut gen = new_encryption_random_generator();

    let mut vec = vec![Scalar::ZERO; 1000];
    let mut retries = 100;
    while retries >= 0 {
        gen.fill_slice_with_random_mask(&mut vec);
        if vec.iter().all(|&x| x != Scalar::ZERO) {
            break;
        }

        retries -= 1;
    }
    assert!(retries != 0);
    assert!(vec.iter().all(|&x| x != Scalar::ZERO));
}

#[test]
fn mask_gen_native_u32() {
    mask_gen_slice_native::<u32>();
}

#[test]
fn mask_gen_native_u64() {
    mask_gen_slice_native::<u64>();
}

#[test]
fn mask_gen_native_u128() {
    mask_gen_slice_native::<u128>();
}

fn mask_gen_slice_custom_mod<Scalar: UnsignedTorus>(ciphertext_modulus: CiphertextModulus<Scalar>) {
    let mut gen = new_encryption_random_generator();

    let mut vec = vec![Scalar::ZERO; 1000];
    let mut retries = 100;
    while retries >= 0 {
        gen.fill_slice_with_random_mask_custom_mod(&mut vec, ciphertext_modulus);
        if vec.iter().all(|&x| x != Scalar::ZERO) {
            break;
        }

        retries -= 1;
    }
    assert!(retries != 0);
    assert!(vec.iter().all(|&x| x != Scalar::ZERO));
    if !ciphertext_modulus.is_native_modulus() {
        let modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        assert!(vec.iter().all(|&x| x < modulus_as_scalar));
    }
}

#[test]
fn mask_gen_slice_custom_mod_u32() {
    mask_gen_slice_custom_mod::<u32>(CiphertextModulus::try_new_power_of_2(31).unwrap());
}

#[test]
fn mask_gen_slice_custom_mod_u64() {
    mask_gen_slice_custom_mod::<u64>(CiphertextModulus::try_new_power_of_2(63).unwrap());
}

#[test]
fn mask_gen_slice_custom_mod_solinas_u64() {
    mask_gen_slice_custom_mod::<u64>(
        CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    );
}

#[test]
fn mask_gen_slice_custom_mod_16_bits_u64() {
    mask_gen_slice_custom_mod::<u64>(CiphertextModulus::try_new(1 << 16).unwrap());
}

#[test]
fn mask_gen_slice_custom_mod_u128() {
    mask_gen_slice_custom_mod::<u128>(CiphertextModulus::try_new_power_of_2(127).unwrap());
}

#[test]
fn mask_gen_slice_native_custom_mod_u32() {
    mask_gen_slice_custom_mod::<u32>(CiphertextModulus::new_native());
}

#[test]
fn mask_gen_slice_native_custom_mod_u64() {
    mask_gen_slice_custom_mod::<u64>(CiphertextModulus::new_native());
}

#[test]
fn mask_gen_slice_native_custom_mod_u128() {
    mask_gen_slice_custom_mod::<u128>(CiphertextModulus::new_native());
}
