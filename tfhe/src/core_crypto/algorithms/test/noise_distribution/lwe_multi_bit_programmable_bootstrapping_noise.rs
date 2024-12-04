use super::*;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::Seed;
use crate::core_crypto::commons::noise_formulas::lwe_multi_bit_programmable_bootstrap::multi_bit_pbs_variance_132_bits_security_gaussian_gf_3;
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::commons::test_tools::{torus_modular_diff, variance};
use npyz::{DType, WriterBuilder};
use rayon::prelude::*;
use std::fs::OpenOptions;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 1;

fn lwe_encrypt_multi_bit_pbs_group_3_decrypt_custom_mod(params: MultiBitTestParams<u64>) {
    type Scalar = u64;
    let input_lwe_dimension = params.input_lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE << message_modulus_log.0;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let pbs_decomposition_base_log = params.decomp_base_log;
    let pbs_decomposition_level_count = params.decomp_level_count;
    let grouping_factor = params.grouping_factor;
    assert_eq!(grouping_factor.0, 3);

    let modulus_as_f64 = if ciphertext_modulus.is_native_modulus() {
        2.0f64.powi(Scalar::BITS as i32)
    } else {
        ciphertext_modulus.get_custom_modulus() as f64
    };

    let expected_variance = multi_bit_pbs_variance_132_bits_security_gaussian_gf_3(
        input_lwe_dimension,
        glwe_dimension,
        polynomial_size,
        pbs_decomposition_base_log,
        pbs_decomposition_level_count,
        modulus_as_f64,
    );

    let mut rsc = {
        let mut deterministic_seeder = Box::new(
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(0)),
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
    let mut noise_samples = Vec::with_capacity(num_samples);

    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

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

    // const ENV_VAR: &str = "TEST_USE_KARATSUBA";

    // let use_karatsuba: u32 = std::env::var(ENV_VAR)
    //     .expect(&format!(
    //         "Set {ENV_VAR} to 1 to use karatsuba, 0 to use fft"
    //     ))
    //     .parse()
    //     .expect(&format!(
    //         "Set {ENV_VAR} to 1 to use karatsuba, 0 to use fft"
    //     ));
    // let use_karatusba = use_karatsuba != 0;

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        let current_run_samples: Vec<_> = (0..NB_TESTS)
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

                let filename = format!("./karatsuba_noise_thread_{thread_id}_input_msg_{msg}.npy");

                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        // 8 == number of bytes
                        .dtype(DType::new_scalar("<i8".parse().unwrap()))
                        .shape(&[
                            karatsuba_noise.len() as u64,
                            karatsuba_noise[0].len() as u64,
                        ])
                        .writer(&mut file)
                        .begin_nd()
                        .unwrap()
                };

                for row in karatsuba_noise.iter() {
                    for col in row.iter().copied() {
                        writer.push(&(col as i64)).unwrap();
                    }
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

                let filename = format!("./fft_noise_thread_{thread_id}_input_msg_{msg}.npy");

                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&filename)
                    .unwrap();

                let mut writer = {
                    npyz::WriteOptions::new()
                        // 8 == number of bytes
                        .dtype(DType::new_scalar("<i8".parse().unwrap()))
                        .shape(&[fft_noise.len() as u64, fft_noise[0].len() as u64])
                        .writer(&mut file)
                        .begin_nd()
                        .unwrap()
                };

                for row in fft_noise.iter() {
                    for col in row.iter().copied() {
                        writer.push(&(col as i64)).unwrap();
                    }
                }

                let last_ext_prod_fft_noise = fft_noise.last().unwrap();

                assert!(check_encrypted_content_respects_mod(
                    &fft_out_ct,
                    ciphertext_modulus
                ));

                let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &karatsuba_out_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                // torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);

                // println!("{last_ext_prod_fft_noise:?}");

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

                // last_ext_prod_karatsuba_noise
                //     .into_iter()
                //     .map(|x| {
                //         let d: f64 = (*x).cast_into();
                //         let d = d / modulus_as_f64;
                //         if d > 0.5 {
                //             d - 1.0
                //         } else {
                //             d
                //         }
                //     })
                //     .collect::<Vec<_>>()
            })
            .flatten()
            .collect();

        noise_samples.extend(current_run_samples);
    }

    let measured_variance = variance(&noise_samples);

    let minimal_variance = minimal_lwe_variance_for_132_bits_security_gaussian(
        fbsk.output_lwe_dimension(),
        if ciphertext_modulus.is_native_modulus() {
            2.0f64.powi(Scalar::BITS as i32)
        } else {
            ciphertext_modulus.get_custom_modulus() as f64
        },
    );

    // Have a log even if it's a test to have a trace in no capture mode to eyeball variances
    println!("measured_variance={measured_variance:?}");
    println!("expected_variance={expected_variance:?}");
    println!("minimal_variance={minimal_variance:?}");

    if measured_variance.0 < expected_variance.0 {
        // We are in the clear as long as we have at least the noise for security
        assert!(
            measured_variance.0 >= minimal_variance.0,
            "Found insecure variance after PBS\n\
            measure_variance={measured_variance:?}\n\
            minimal_variance={minimal_variance:?}"
        );
    } else {
        // Check we are not too far from the expected variance if we are bigger
        let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
        let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;

        assert!(
            var_abs_diff < tolerance_threshold,
            "Absolute difference for variance: {var_abs_diff}, \
            tolerance threshold: {tolerance_threshold}, \
            got variance: {measured_variance:?}, \
            expected variance: {expected_variance:?}"
        );
    }
}

#[test]
fn test_lwe_encrypt_multi_bit_pbs_group_3_decrypt_custom_mod_noise_test_params_multi_bit_group_3_4_bits_native_u64_132_bits_gaussian(
) {
    lwe_encrypt_multi_bit_pbs_group_3_decrypt_custom_mod(
        NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN,
    )
}
