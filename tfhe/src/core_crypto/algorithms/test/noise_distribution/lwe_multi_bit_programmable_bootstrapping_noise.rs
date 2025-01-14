use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::Seed;
use crate::core_crypto::commons::noise_formulas::lwe_multi_bit_programmable_bootstrap::*;
use crate::core_crypto::commons::noise_formulas::secure_noise::*;
use crate::core_crypto::commons::test_tools::{variance};
use npyz::{DType, WriterBuilder};
use rayon::prelude::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::fs::File;
use std::mem::discriminant;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 500;
const EXP_NAME: &str = "fft-with-gap";   // wide-search-2000-gauss   gpu-gauss   gpu-tuniform

fn lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(
    params: &MultiBitTestParams<u64>,
    run_measurements: &bool,
) {
    type Scalar = u64;
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
    let grouping_factor = params.grouping_factor;
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

    let (expected_variance_kara,expected_variance_fft) = noise_prediction_kara_fft(params);

    // 3 sigma                            > half   interval size (msg-mod    +    padding bit)
    if 3.0*expected_variance_fft.0.sqrt() > 0.5 / (2usize.pow(message_modulus_log.0 as u32 + 1) as f64) {return;}

    // output predicted noises to JSON
    export_noise_predictions(params);
    if !run_measurements {return;}

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
    // shall not play any role
    //~ // rewrite with fixed Hamming weight secret (n.b., with odd dimension, this is not exactly 1/2 !!)
    //~ input_lwe_secret_key.as_mut().fill(0);
    //~ input_lwe_secret_key.as_mut()[..lwe_dimension/2].fill(1);

    // generate pseudo-random secret
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    // shall not play any role either
    //~ // rewrite with fixed Hamming weight secret (n.b., with odd dimension, this is not exactly 1/2 !!)
    //~ let output_glwe_secret_key_len = output_glwe_secret_key.as_ref().len();
    //~ output_glwe_secret_key.as_mut().fill(0);
    //~ output_glwe_secret_key.as_mut()[..output_glwe_secret_key_len/2].fill(1);

    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    let (bsk, fbsk) = {
        let bsk = allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            pbs_decomposition_base_log,
            pbs_decomposition_level_count,
            grouping_factor,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let mut fbsk = FourierLweMultiBitBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            bsk.grouping_factor(),
        );

        par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fbsk);

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

    let mut sanity_plain = PlaintextList::new(0, PlaintextCount(accumulator.polynomial_size().0));

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

                let karatsuba_noise = karatsuba_multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut karatsuba_out_ct,
                    &accumulator,
                    &bsk,
                    params.thread_count,
                    Some((
                        &input_lwe_secret_key,
                        &output_glwe_secret_key,
                        &reference_accumulator,
                    )),
                );

                let filename_kara = format!("./results/{EXP_NAME}/samples/kara-id={thread_id}-gf={}-logB={}-l={}-k={}-N={}-distro={distro}.npy", grouping_factor.0, pbs_decomposition_base_log.0, pbs_decomposition_level_count.0, glwe_dimension.0, polynomial_size.0);

                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename_kara)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        // 8 == number of bytes
                        .dtype(DType::new_scalar("<i8".parse().unwrap()))
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
                    writer.push(&(row[0] as i64)).unwrap();   // essentially SE
                }
                //TODO close file?

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

                let fft_noise = multi_bit_programmable_bootstrap_lwe_ciphertext_return_noise(
                    &lwe_ciphertext_in,
                    &mut fft_out_ct,
                    &accumulator,
                    &fbsk,
                    params.thread_count,
                    Some((
                        &input_lwe_secret_key,
                        &output_glwe_secret_key,
                        &reference_accumulator,
                    )),
                );

                let filename_fft = format!("./results/{EXP_NAME}/samples/fft-id={thread_id}-gf={}-logB={}-l={}-k={}-N={}-distro={distro}.npy", grouping_factor.0, pbs_decomposition_base_log.0, pbs_decomposition_level_count.0, glwe_dimension.0, polynomial_size.0);

                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename_fft)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        // 8 == number of bytes
                        .dtype(DType::new_scalar("<i8".parse().unwrap()))
                        .shape(&[
                            fft_noise.len() as u64,
                            //~ fft_noise[0].len() as u64
                            1u64
                        ])
                        .writer(&mut file)
                        .begin_nd()
                        .unwrap()
                };

                for row in fft_noise.iter() {
                    //~ for col in row.iter().copied() {
                        //~ writer.push(&(col as i64)).unwrap();
                    //~ }
                    writer.push(&(row[0] as i64)).unwrap();   // essentially SE
                }

                let last_ext_prod_fft_noise = fft_noise.last().unwrap();

                assert!(check_encrypted_content_respects_mod(
                    &fft_out_ct,
                    ciphertext_modulus
                ));

                let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &karatsuba_out_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                //TODO FIXME uncomment !!
                //~ assert_eq!(decoded, f(msg));

                // torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);

                // println!("{last_ext_prod_fft_noise:?}");

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

        noise_samples_kara.extend(current_run_samples_kara_fft.clone().into_iter().map(|s|{s.0}));
        noise_samples_fft.extend(current_run_samples_kara_fft.into_iter().map(|s|{s.1}));
    }

    let measured_variance_fft = variance(&noise_samples_fft);
    let measured_variance_kara = variance(&noise_samples_kara);

    //TODO add TUniform
    let minimal_variance = minimal_lwe_variance_for_132_bits_security_gaussian(
        fbsk.output_lwe_dimension(),
        if ciphertext_modulus.is_native_modulus() {
            2.0f64.powi(Scalar::BITS as i32)
        } else {
            ciphertext_modulus.get_custom_modulus() as f64
        },
    );

    println!("Finished parameters {params:?}");

    //TODO uncomment, at some point
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

fn export_noise_predictions(params: &MultiBitTestParams<u64>) {
    // output predicted noises to JSON
    let distro: &str = if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
        "GAUSSIAN"
    } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
        "TUNIFORM"
    } else {
        panic!("Unknown distribution: {}", params.lwe_noise_distribution)
    };
    let filename_exp_var = format!("./results/{EXP_NAME}/expected-variances-gf={}-logB={}-l={}-k={}-N={}-distro={distro}.json", params.grouping_factor.0, params.pbs_base_log.0, params.pbs_level.0, params.glwe_dimension.0, params.polynomial_size.0);
    let mut file_exp_var = File::create(&filename_exp_var).unwrap();

    let (expected_variance_kara,expected_variance_fft) = noise_prediction_kara_fft(params);

    file_exp_var.write_all(
        format!(r#"{{
    "lwe_dimension": {},
    "grouping_factor": {},
    "log_base": {},
    "level": {},
    "glwe_dimension": {},
    "polynomial_degree": {},
    "distribution": "{}",
    "expected_variance_kara": {},
    "expected_variance_fft": {}
}}"#,
            params.lwe_dimension.0,
            params.grouping_factor.0,
            params.pbs_base_log.0,
            params.pbs_level.0,
            params.glwe_dimension.0,
            params.polynomial_size.0,
            distro,
            expected_variance_kara.0,
            expected_variance_fft.0,
        ).as_bytes()
    ).unwrap();
}

//TODO make this somehow a bit more compact
fn noise_prediction_kara_fft(params: &MultiBitTestParams<u64>) -> (Variance,Variance) {
    type Scalar = u64;
    let modulus_as_f64 = if params.ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(Scalar::BITS as i32)
    } else {
        params.ciphertext_modulus.get_custom_modulus() as f64
    };
    return (
        if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
            match params.grouping_factor.0 {
                2 => pbs_variance_132_bits_security_gaussian_gf_2_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                3 => pbs_variance_132_bits_security_gaussian_gf_3_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                4 => pbs_variance_132_bits_security_gaussian_gf_4_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                _ => panic!("Unsupported grouping factor: {}", params.grouping_factor.0),
            }
        } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
            match params.grouping_factor.0 {
                2 => pbs_variance_132_bits_security_tuniform_gf_2_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                3 => pbs_variance_132_bits_security_tuniform_gf_3_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                4 => pbs_variance_132_bits_security_tuniform_gf_4_exact_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                _ => panic!("Unsupported grouping factor: {}", params.grouping_factor.0),
            }
        } else {
            panic!("Unknown distribution: {:?}", params.lwe_noise_distribution)
        },
        if let DynamicDistribution::Gaussian(_) = params.lwe_noise_distribution {
            match params.grouping_factor.0 {
                2 => pbs_variance_132_bits_security_gaussian_gf_2_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                3 => pbs_variance_132_bits_security_gaussian_gf_3_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                4 => pbs_variance_132_bits_security_gaussian_gf_4_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                _ => panic!("Unsupported grouping factor: {}", params.grouping_factor.0),
            }
        } else if let DynamicDistribution::TUniform(_) = params.lwe_noise_distribution {
            match params.grouping_factor.0 {
                2 => pbs_variance_132_bits_security_tuniform_gf_2_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                3 => pbs_variance_132_bits_security_tuniform_gf_3_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                4 => pbs_variance_132_bits_security_tuniform_gf_4_fft_mul(
                    params.lwe_dimension,
                    params.glwe_dimension,
                    params.polynomial_size,
                    params.pbs_base_log,
                    params.pbs_level,
                    modulus_as_f64,
                ),
                _ => panic!("Unsupported grouping factor: {}", params.grouping_factor.0),
            }
        } else {
            panic!("Unknown distribution: {:?}", params.lwe_noise_distribution)
        }
    );
}

#[test]
fn test_lwe_encrypt_multi_bit_pbs_decrypt_custom_mod_noise_test_params_multi_bit_4_bits_native_u64_132_bits() {
    test_impl(true);
}

#[test]
fn test_export_multi_bit_noise_predictions() {
    test_impl(false);
}

fn test_impl(run_measurements: bool) {
    //TODO FIXME: params need to be updated, cf. mod.rs where they are defined
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_2_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_4_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_6_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_2_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_2_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_4_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_6_BITS_NATIVE_U64_132_BITS_TUNIFORM);
    //~ return;
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_2_BITS_NATIVE_U64_132_BITS_GAUSSIAN);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN);
    //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_GAUSSIAN);
    //~ return;

    for gf in [2,3,4] {
    for logbase in 5..=30 {
    for level in 1..=6 {
        if logbase * level > 36 {continue;}   // also used: logbase * level < 15
        //~ for (k,logN) in [(3,9),(4,9),(1,10),(2,10),(1,11)].iter() {
        for (k,logN) in [(4,9),(2,10),(1,11),(3,10),(2,11),(1,12),(1,13),].iter() {
            //~ // skip those not interesting                                                             1 is here to make a margin
            //~ if ((logbase*(level+1)) as f64) < 53_f64 - *logN as f64 - (((k+1)*level) as f64).log2() - 1_f64 || logbase * level > 36 {
                //~ println!("Early-discarded: l={level}, logB={logbase}, (k,N)=({k},{})", 1<<*logN);
                //~ continue;
            //~ }

            // Gaussian noise
            let glwe_var = minimal_glwe_variance_for_132_bits_security_gaussian(GlweDimension(*k), PolynomialSize(1<<logN), 2.0_f64.powf(64.0));   // TODO CiphertextModulus::new_native() ???
            let gaussian_params: MultiBitTestParams<u64> = MultiBitTestParams {
                lwe_dimension: LweDimension(100 * gf),
                lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                    1.4742441118914234e-06 // this shall play no role, right..?
                )),
                pbs_base_log: DecompositionBaseLog(logbase),
                pbs_level: DecompositionLevelCount(level),
                glwe_dimension: GlweDimension(*k),
                polynomial_size: PolynomialSize(1 << logN),
                glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(glwe_var.get_standard_dev())),
                message_modulus_log: MessageModulusLog(4),
                ciphertext_modulus: CiphertextModulus::new_native(),
                grouping_factor: LweBskGroupingFactor(gf),
                thread_count: ThreadCount(12),
            };

            // skip those that predict FFT noise <10% of the overall noise
            let (exp_var_kara,exp_var_fft) = noise_prediction_kara_fft(&gaussian_params);
            if exp_var_fft.0 < exp_var_kara.0 * 1.1 {
                println!("FFT-ratio-discarded: l={level}, logB={logbase}, (k,N)=({k},{})", 1<<logN);
                continue;
            }
            lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&gaussian_params, &run_measurements);

            //~ // TUniform noise
            //~ let glwe_bnd = minimal_glwe_bound_for_132_bits_security_tuniform(GlweDimension(*k), PolynomialSize(1<<logN), 2.0_f64.powf(64.0));
            //~ let tuniform_params: MultiBitTestParams<u64> = MultiBitTestParams {
                //~ lwe_dimension: LweDimension(100 * gf),
                //~ lwe_noise_distribution: DynamicDistribution::new_t_uniform(10), // this shall play no role, right..?
                //~ decomp_base_log: DecompositionBaseLog(logbase),
                //~ decomp_level_count: DecompositionLevelCount(level),
                //~ glwe_dimension: GlweDimension(*k),
                //~ polynomial_size: PolynomialSize(1 << logN),
                //~ glwe_noise_distribution: DynamicDistribution::new_t_uniform(glwe_bnd),
                //~ message_modulus_log: MessageModulusLog(4),
                //~ ciphertext_modulus: CiphertextModulus::new_native(),
                //~ grouping_factor: LweBskGroupingFactor(gf),
                //~ thread_count: ThreadCount(12),
            //~ };
            //~ lwe_encrypt_multi_bit_pbs_decrypt_custom_mod(&tuniform_params, &run_measurements);
        }
    }
    }
    }
}
