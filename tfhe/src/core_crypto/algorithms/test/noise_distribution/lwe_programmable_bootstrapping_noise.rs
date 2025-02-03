use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::{RandomGenerable, Seed};
use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::*;
use crate::core_crypto::commons::noise_formulas::secure_noise::*;
use crate::core_crypto::commons::numeric;
use crate::core_crypto::commons::test_tools::variance;
use crate::core_crypto::prelude::UnsignedInteger;
use npyz::{DType, WriterBuilder};
use rayon::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::any::TypeId;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem::discriminant;
use std::path::PathBuf;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 500;
const EXP_NAME: &str = "fft-with-gap"; // wide-search-2000-gauss   gpu-gauss   gpu-tuniform

#[derive(Clone, Debug)]
enum FourierBsk {
    F64(FourierLweBootstrapKeyOwned),
    F128(Fourier128LweBootstrapKeyOwned),
}

fn lwe_encrypt_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: &ClassicTestParams<Scalar>,
    run_measurements: &bool,
) where
    usize: numeric::CastFrom<Scalar>,
{
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let pbs_decomposition_base_log = params.pbs_base_log;
    let pbs_decomposition_level_count = params.pbs_level;
    assert_eq!(
        discriminant(&lwe_noise_distribution),
        discriminant(&glwe_noise_distribution),
        "Noises are not of the same variant"
    );
    let distro: &str = if let DynamicDistribution::Gaussian(_) = lwe_noise_distribution {
        "GAUSSIAN"
    } else if let DynamicDistribution::TUniform(_) = lwe_noise_distribution {
        "TUNIFORM"
    } else {
        panic!("Unknown distribution: {lwe_noise_distribution:?}")
    };

    let modulus_as_f64 = if ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(Scalar::BITS as i32)
    } else {
        ciphertext_modulus.get_custom_modulus() as f64
    };

    // output predicted noises to JSON
    export_noise_predictions::<Scalar>(params);
    if !run_measurements {
        return;
    }

    let mut rsc = {
        let mut deterministic_seeder = Box::new(
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(420)),
        );
        let encryption_random_generator = EncryptionRandomGenerator::new(
            deterministic_seeder.seed(),
            deterministic_seeder.as_mut(),
        );
        let secret_random_generator = SecretRandomGenerator::new(deterministic_seeder.seed());
        TestResources {
            seeder: deterministic_seeder,
            encryption_random_generator,
            secret_random_generator,
        }
    };

    let f = |x: Scalar| x;

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples_fft = Vec::with_capacity(num_samples);
    let mut noise_samples_kara = Vec::with_capacity(num_samples);

    // generate pseudo-random secret
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    // generate pseudo-random secret
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    let (bsk, fbsk) = {
        let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            pbs_decomposition_base_log,
            pbs_decomposition_level_count,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let fbsk: FourierBsk = if TypeId::of::<Scalar>() == TypeId::of::<u128>() {
            let mut inner_fbsk = Fourier128LweBootstrapKey::new(
                bsk.input_lwe_dimension(),
                bsk.glwe_size(),
                bsk.polynomial_size(),
                bsk.decomposition_base_log(),
                bsk.decomposition_level_count(),
            );

            convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut inner_fbsk);

            FourierBsk::F128(inner_fbsk)
        } else {
            let mut inner_fbsk = FourierLweBootstrapKey::new(
                bsk.input_lwe_dimension(),
                bsk.glwe_size(),
                bsk.polynomial_size(),
                bsk.decomposition_base_log(),
                bsk.decomposition_level_count(),
            );

            par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut inner_fbsk);

            FourierBsk::F64(inner_fbsk)
        };

        (bsk, fbsk)
    };

    let mut accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    let reference_accumulator = accumulator.clone();

    let ref_acc_plain = accumulator.get_body().as_ref().to_vec();

    // noiseless GLWE encryption of LUT ... s.t. mask|body are random instead of zeros|plain-LUT
    let zero_noise = Gaussian::from_dispersion_parameter(Variance(0.0), 0.0);
    encrypt_glwe_ciphertext_assign(
        &output_glwe_secret_key,
        &mut accumulator,
        zero_noise,
        &mut rsc.encryption_random_generator,
    );

    let mut sanity_plain = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(accumulator.polynomial_size().0),
    );

    decrypt_glwe_ciphertext(&output_glwe_secret_key, &accumulator, &mut sanity_plain);

    let dec_sanity = sanity_plain.as_ref().to_vec();

    assert_eq!(ref_acc_plain, dec_sanity);

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    while msg != Scalar::ZERO {
        // msg = msg.wrapping_sub(Scalar::ONE);
        msg = Scalar::ZERO;

        println!("Acquiring {NB_TESTS} samples for \"{EXP_NAME}\" experiment ...");

        let current_run_samples_kara_fft: Vec<_> = (0..NB_TESTS)
            .into_par_iter()
            .map(|thread_id| {
                let mut rsc = TestResources::new();

                let plaintext = Plaintext(msg * delta);

                let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    plaintext,
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.encryption_random_generator,
                );

                assert!(check_encrypted_content_respects_mod(
                    &lwe_ciphertext_in,
                    ciphertext_modulus
                ));

                let mut karatsuba_out_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                // Karatsuba functions support both u64 & u128
                let karatsuba_noise = karatsuba_programmable_bootstrap_lwe_ciphertext_return_noise(
                    &lwe_ciphertext_in,
                    &mut karatsuba_out_ct,
                    &accumulator,
                    &bsk,
                    Some((
                        &input_lwe_secret_key,
                        &output_glwe_secret_key,
                        &reference_accumulator,
                    )),
                );

                let filename_kara = format!("./results/{EXP_NAME}/samples/kara-id={thread_id}-gf=1-logB={}-l={}-k={}-N={}-distro={}-logQ={}.npy", pbs_decomposition_base_log.0, pbs_decomposition_level_count.0, glwe_dimension.0, polynomial_size.0, distro, Scalar::BITS);

                let mut filename_kara_path: PathBuf = filename_kara.as_str().into();
                let filename_kara_parent = filename_kara_path.parent().unwrap();
                std::fs::create_dir_all(&filename_kara_parent).unwrap();
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename_kara)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        .dtype(DType::new_scalar(">f8".parse().unwrap()))
                        .shape(&[
                            karatsuba_noise.len() as u64,
                            //~ karatsuba_noise[0].len() as u64,
                            1u64,
                        ])
                        .writer(&mut file)
                        .begin_nd()
                        .unwrap()
                };

                for row in karatsuba_noise.iter() {
                    //~ for col in row.iter().copied() {
                        //~ writer.push(&(col as i64)).unwrap();
                    //~ }
                    let noise_as_float: f64 = row[0].into_signed().cast_into() / modulus_as_f64;
                    writer.push(&(noise_as_float)).unwrap();   // essentially SE
                }

                let last_ext_prod_karatsuba_noise = karatsuba_noise.last().unwrap();

                assert!(check_encrypted_content_respects_mod(
                    &karatsuba_out_ct,
                    ciphertext_modulus
                ));

                let mut fft_out_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                // different FFT functions for u64 & u128
                let fft_noise = match &fbsk {
                    FourierBsk::F64(fbsk) => programmable_bootstrap_lwe_ciphertext_return_noise(
                        &lwe_ciphertext_in,
                        &mut fft_out_ct,
                        &accumulator,
                        &fbsk,
                        Some((
                            &input_lwe_secret_key,
                            &output_glwe_secret_key,
                            &reference_accumulator,
                        )),
                    ),
                    FourierBsk::F128(fbsk) => programmable_bootstrap_f128_lwe_ciphertext_return_noise(
                        &lwe_ciphertext_in,
                        &mut fft_out_ct,
                        &accumulator,
                        &fbsk,
                        Some((
                            &input_lwe_secret_key,
                            &output_glwe_secret_key,
                            &reference_accumulator,
                        )),
                    ),
                };

                let filename_fft = format!("./results/{EXP_NAME}/samples/fft-id={thread_id}-gf=1-logB={}-l={}-k={}-N={}-distro={}-logQ={}.npy", pbs_decomposition_base_log.0, pbs_decomposition_level_count.0, glwe_dimension.0, polynomial_size.0, distro, Scalar::BITS);

                let mut filename_fft_path: PathBuf = filename_fft.as_str().into();
                let filename_fft_parent = filename_fft_path.parent().unwrap();
                std::fs::create_dir_all(&filename_fft_parent).unwrap();
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename_fft)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        .dtype(DType::new_scalar(">f8".parse().unwrap()))
                        .shape(&[
                            fft_noise.len() as u64,
                            //~ fft_noise[0].len() as u64,
                            1u64,
                        ])
                        .writer(&mut file)
                        .begin_nd()
                        .unwrap()
                };

                for row in fft_noise.iter() {
                    //~ for col in row.iter().copied() {
                        //~ writer.push(&(col as i64)).unwrap();
                    //~ }
                    let noise_as_float: f64 = row[0].into_signed().cast_into() / modulus_as_f64;
                    writer.push(&(noise_as_float)).unwrap();   // essentially SE
                }

                let last_ext_prod_fft_noise = fft_noise.last().unwrap();

                assert!(check_encrypted_content_respects_mod(
                    &fft_out_ct,
                    ciphertext_modulus
                ));

                let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &karatsuba_out_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                //TODO FIXME uncomment !!
                //~ let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &karatsuba_out_ct);
                //~ let decoded = round_decode(decrypted.0, delta) % msg_modulus;
                //~ assert_eq!(decoded, f(msg));

                // output a tuple with (Kara-noises, FFT-noises)
                (
                    last_ext_prod_karatsuba_noise
                        .into_iter()
                        .map(|x| {
                            let d: f64 = (*x).cast_into();
                            let d = d / modulus_as_f64;
                            if d > 0.5 {
                                d - 1.0
                            } else {
                                d
                            }
                        })
                        .collect::<Vec<_>>(),
                    last_ext_prod_fft_noise
                        .into_iter()
                        .map(|x| {
                            let d: f64 = (*x).cast_into();
                            let d = d / modulus_as_f64;
                            if d > 0.5 {
                                d - 1.0
                            } else {
                                d
                            }
                        })
                        .collect::<Vec<_>>()
                )
            })
            .flatten()
            .collect();

        noise_samples_kara.extend(
            current_run_samples_kara_fft
                .clone()
                .into_iter()
                .map(|s| s.0),
        );
        noise_samples_fft.extend(current_run_samples_kara_fft.into_iter().map(|s| s.1));
    }

    println!("Finished parameters {params:?}");

    //TODO write these values somewhere?
    //~ let measured_variance_fft = variance(&noise_samples_fft);
    //~ let measured_variance_kara = variance(&noise_samples_kara);

    //TODO add TUniform?
    //TODO uncomment, at some point
    //~ let minimal_variance = minimal_lwe_variance_for_132_bits_security_gaussian(
    //~ fbsk.output_lwe_dimension(),
    //~ modulus_as_f64,
    //~ );
    //~ if measured_variance_fft.0 < expected_variance_fft.0 {
    //~ // We are in the clear as long as we have at least the noise for security
    //~ assert!(
    //~ measured_variance_fft.0 >= minimal_variance.0,
    //~ "Found insecure variance after PBS\n\
    //~ measure_variance={measured_variance_fft:?}\n\
    //~ minimal_variance={minimal_variance:?}"
    //~ );
    //~ } else {
    //~ // Check we are not too far from the expected variance if we are bigger
    //~ let var_abs_diff = (expected_variance_fft.0 - measured_variance_fft.0).abs();
    //~ let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance_fft.0;
    //~ assert!(
    //~ var_abs_diff < tolerance_threshold,
    //~ "Absolute difference for variance: {var_abs_diff}, \
    //~ tolerance threshold: {tolerance_threshold}, \
    //~ got variance: {measured_variance_fft:?}, \
    //~ expected variance w/ FFT: {expected_variance_fft:?}"
    //~ );
    //~ }
}

fn export_noise_predictions<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: &ClassicTestParams<Scalar>,
) {
    // output predicted noises to JSON
    let distro: &str = if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
        "GAUSSIAN"
    } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
        "TUNIFORM"
    } else {
        panic!("Unknown distribution: {}", params.lwe_noise_distribution)
    };
    let log_q = if params.ciphertext_modulus.is_native_modulus() {
        Scalar::BITS as u32
    } else {
        params.ciphertext_modulus.get_custom_modulus().ilog2()
    };
    let filename_exp_var = format!(
        "./results/{EXP_NAME}/expected-variances-gf=1-logB={}-l={}-k={}-N={}-distro={distro}-logQ={}.json",
        params.pbs_base_log.0,
        params.pbs_level.0,
        params.glwe_dimension.0,
        params.polynomial_size.0,
        log_q,
    );
    let mut file_exp_var = File::create(&filename_exp_var).unwrap();

    let (expected_variance_kara, expected_variance_fft) =
        noise_prediction_kara_fft::<Scalar>(params);

    file_exp_var
        .write_all(
            format!(
                r#"{{
    "lwe_dimension": {},
    "log_base": {},
    "level": {},
    "glwe_dimension": {},
    "polynomial_degree": {},
    "distribution": "{}",
    "expected_variance_kara": {},
    "expected_variance_fft": {}
}}"#,
                params.lwe_dimension.0,
                params.pbs_base_log.0,
                params.pbs_level.0,
                params.glwe_dimension.0,
                params.polynomial_size.0,
                distro,
                expected_variance_kara.0,
                expected_variance_fft.0,
            )
            .as_bytes(),
        )
        .unwrap();
}

//TODO make this somehow a bit more compact
fn noise_prediction_kara_fft<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: &ClassicTestParams<Scalar>,
) -> (Variance, Variance) {
    if !params.ciphertext_modulus.is_native_modulus() {
        panic!("With FFT, only native modulus is supported.")
    }
    let modulus_as_f64 = 2.0f64.powi(Scalar::BITS as i32);
    let mantissa_size_as_f64 = if Scalar::BITS == 64 {
        53_f64
    } else if Scalar::BITS == 128 {
        104_f64 //TODO check this (also make sure Sarah's impl is used, not the quadruple type,
                // mantissa size of which is 112+1
    } else {
        panic!(
            "Unexpected bit-len of ciphertext modulus: {:?}",
            Scalar::BITS
        )
    };
    return (
        if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
            pbs_variance_132_bits_security_gaussian_exact_mul(
                params.lwe_dimension,
                params.glwe_dimension,
                params.polynomial_size,
                params.pbs_base_log,
                params.pbs_level,
                modulus_as_f64,
            )
        } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
            pbs_variance_132_bits_security_tuniform_exact_mul(
                params.lwe_dimension,
                params.glwe_dimension,
                params.polynomial_size,
                params.pbs_base_log,
                params.pbs_level,
                modulus_as_f64,
            )
        } else {
            panic!("Unknown distribution: {:?}", params.lwe_noise_distribution)
        },
        if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
            pbs_variance_132_bits_security_gaussian_fft_mul(
                params.lwe_dimension,
                params.glwe_dimension,
                params.polynomial_size,
                params.pbs_base_log,
                params.pbs_level,
                mantissa_size_as_f64,
                modulus_as_f64,
            )
        } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
            pbs_variance_132_bits_security_tuniform_fft_mul(
                params.lwe_dimension,
                params.glwe_dimension,
                params.polynomial_size,
                params.pbs_base_log,
                params.pbs_level,
                mantissa_size_as_f64,
                modulus_as_f64,
            )
        } else {
            panic!("Unknown distribution: {:?}", params.lwe_noise_distribution)
        },
    );
}

#[test]
fn test_lwe_encrypt_pbs_decrypt_custom_mod_noise_test_params_4_bits_native_u64_132_bits() {
    test_impl::<u64>(true);
}
#[test]
fn test_lwe_encrypt_pbs_decrypt_custom_mod_noise_test_params_4_bits_native_u128_132_bits() {
    test_impl::<u128>(true);
}

#[test]
fn test_export_noise_predictions_native_u64_132_bits() {
    test_impl::<u64>(false);
}
#[test]
fn test_export_noise_predictions_native_u128_132_bits() {
    test_impl::<u128>(false);
}

fn test_impl<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    run_measurements: bool,
) where
    usize: CastFrom<Scalar>,
{
    //TODO FIXME: params need to be updated, cf. mod.rs where they are defined
    //~ lwe_encrypt_pbs_decrypt_custom_mod<Scalar>(&
    //~ NOISE_TEST_PARAMS_2_BITS_NATIVE_U64_132_BITS_TUNIFORM); return;
    let modulus_as_f64 = 2.0f64.powi(Scalar::BITS as i32);
    let msg_mod_log = 4;

    for logbase in 5..=30 {
        for level in 1..=6 {
            if logbase * level > 36 {
                continue;
            } // also used: logbase * level < 15
              //~ for (k,logN) in [(3,9),(4,9),(1,10),(2,10),(1,11)].iter() {
            for (k,logN) in [(4,9),(2,10),(1,11),(3,10),(2,11),(1,12),(1,13),].iter() {
            //~ // skip those not interesting                                                             1 is here to make a margin
            //~ if ((logbase*(level+1)) as f64) < 53_f64 - *logN as f64 - (((k+1)*level) as f64).log2() - 1_f64 || logbase * level > 36 {
                //~ println!("Early-discarded: l={level}, logB={logbase}, (k,N)=({k},{})", 1<<*logN);
                //~ continue;
            //~ }

            // Gaussian noise
            let glwe_var = minimal_glwe_variance_for_132_bits_security_gaussian(GlweDimension(*k), PolynomialSize(1<<logN), modulus_as_f64);   // TODO put after defining gaussian_params with CiphertextModulus::new_native() ???
            let gaussian_params: ClassicTestParams<Scalar> = ClassicTestParams {
                lwe_dimension: LweDimension(100),
                lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                    1.4742441118914234e-06 // this shall play no role, right..?
                )),
                pbs_base_log: DecompositionBaseLog(logbase),
                pbs_level: DecompositionLevelCount(level),
                glwe_dimension: GlweDimension(*k),
                polynomial_size: PolynomialSize(1 << logN),
                glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(glwe_var.get_standard_dev())),
                message_modulus_log: MessageModulusLog(msg_mod_log),
                ciphertext_modulus: CiphertextModulus::<Scalar>::new_native(),   //TODO remove generics?
                // unused param's
                ks_level: DecompositionLevelCount(0),
                ks_base_log: DecompositionBaseLog(0),
                pfks_level: DecompositionLevelCount(0),
                pfks_base_log: DecompositionBaseLog(0),
                pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
                cbs_level: DecompositionLevelCount(0),
                cbs_base_log: DecompositionBaseLog(0),
            };

            // skip those that predict FFT noise <10% of the overall noise
            let (exp_var_kara,exp_var_fft) = noise_prediction_kara_fft::<Scalar>(&gaussian_params);

            // 3 sigma                  > half   interval size (msg-mod    +    padding bit)
            if 3.0*exp_var_fft.0.sqrt() > 0.5 / (2usize.pow(msg_mod_log as u32 + 1) as f64) {
                println!("3-sigma-discarded:   l={level}, logB={logbase}, (k,N)=({k},{})", 1<<logN);
                continue;
            }
            if exp_var_fft.0 < exp_var_kara.0 * 1.1 {
                println!("FFT-ratio-discarded: l={level}, logB={logbase}, (k,N)=({k},{})", 1<<logN);
                continue;
            }
            lwe_encrypt_pbs_decrypt_custom_mod::<Scalar>(&gaussian_params, &run_measurements);

            //~ // TUniform noise
            //~ let glwe_bnd = minimal_glwe_bound_for_132_bits_security_tuniform(GlweDimension(*k), PolynomialSize(1<<logN), 2.0_f64.powf(64.0));
            //~ let tuniform_params: ClassicTestParams<Scalar> = ClassicTestParams {
                //~ lwe_dimension: LweDimension(100),
                //~ lwe_noise_distribution: DynamicDistribution::new_t_uniform(10), // this shall play no role, right..?
                //~ decomp_base_log: DecompositionBaseLog(logbase),
                //~ decomp_level_count: DecompositionLevelCount(level),
                //~ glwe_dimension: GlweDimension(*k),
                //~ polynomial_size: PolynomialSize(1 << logN),
                //~ glwe_noise_distribution: DynamicDistribution::new_t_uniform(glwe_bnd),
                //~ message_modulus_log: MessageModulusLog(4),
                //~ CiphertextModulus::<Scalar>::new_native(),   //TODO remove generics?
                //~ // unused param's
                //~ ks_level: DecompositionLevelCount(0),
                //~ ks_base_log: DecompositionBaseLog(0),
                //~ pfks_level: DecompositionLevelCount(0),
                //~ pfks_base_log: DecompositionBaseLog(0),
                //~ pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
                //~ cbs_level: DecompositionLevelCount(0),
                //~ cbs_base_log: DecompositionBaseLog(0),
            //~ };
            //~ lwe_encrypt_pbs_decrypt_custom_mod<Scalar>(&tuniform_params, &run_measurements);
        }
        }
    }
}
