//~ use super::*;
//~ use crate::core_crypto::commons::generators::DeterministicSeeder;
//~ use crate::core_crypto::commons::math::random::Seed;
//~ use crate::core_crypto::commons::noise_formulas::lwe_programmable_bootstrap::*;
//~ use crate::core_crypto::commons::noise_formulas::secure_noise::*;
//~ use crate::core_crypto::commons::test_tools::{variance};
//~ use npyz::{DType, WriterBuilder};
//~ use rayon::prelude::*;
//~ use std::fs::OpenOptions;
//~ use std::io::Write;
//~ use std::fs::File;
//~ use std::mem::discriminant;

//~ // This is 1 / 16 which is exactly representable in an f64 (even an f32)
//~ // 1 / 32 is too strict and fails the tests
//~ const RELATIVE_TOLERANCE: f64 = 0.0625;

//~ const NB_TESTS: usize = 500;
//~ const EXP_NAME: &str = "fft-with-gap";   // wide-search-2000-gauss   gpu-gauss   gpu-tuniform

//~ fn lwe_encrypt_pbs_decrypt_custom_mod<Scalar>(
    //~ params: ClassicTestParams<Scalar>,
    //~ run_measurements: &bool,
//~ ) where
    //~ Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
//~ {
    //~ let input_lwe_dimension = params.lwe_dimension;
    //~ let lwe_noise_distribution = params.lwe_noise_distribution;
    //~ let glwe_noise_distribution = params.glwe_noise_distribution;
    //~ let ciphertext_modulus = params.ciphertext_modulus;
    //~ let message_modulus_log = params.message_modulus_log;
    //~ let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    //~ let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    //~ let glwe_dimension = params.glwe_dimension;
    //~ let polynomial_size = params.polynomial_size;
    //~ let pbs_decomposition_base_log = params.pbs_base_log;
    //~ let pbs_decomposition_level_count = params.pbs_level;
    //~ assert_eq!(
        //~ discriminant(&lwe_noise_distribution),
        //~ discriminant(&glwe_noise_distribution),
        //~ "Noises are not of the same variant"
    //~ );
    //~ let distro: &str = if let DynamicDistribution::Gaussian(_) = lwe_noise_distribution {
        //~ "GAUSSIAN"
    //~ } else if let DynamicDistribution::TUniform(_) = lwe_noise_distribution {
        //~ "TUNIFORM"
    //~ } else {
        //~ panic!("Unknown distribution: {lwe_noise_distribution:?}")
    //~ };

    //~ let modulus_as_f64 = if ciphertext_modulus.is_native_modulus() {
        //~ 2.0f64.powi(Scalar::BITS as i32)
    //~ } else {
        //~ ciphertext_modulus.get_custom_modulus() as f64
    //~ };

    //~ let (expected_variance_kara,expected_variance_fft) = noise_prediction_kara_fft(params);

    //~ // 3 sigma                            > half   interval size (msg-mod    +    padding bit)
    //~ if 3.0*expected_variance_fft.0.sqrt() > 0.5 / (2usize.pow(message_modulus_log.0 as u32 + 1) as f64) {return;}

    //~ // output predicted noises to JSON
    //~ export_noise_predictions(params);
    //~ if !run_measurements {return;}

    //~ let mut rsc = {
        //~ let mut deterministic_seeder = Box::new(
            //~ DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(420)),
        //~ );
        //~ let encryption_random_generator = EncryptionRandomGenerator::new(
            //~ deterministic_seeder.seed(),
            //~ deterministic_seeder.as_mut(),
        //~ );
        //~ let secret_random_generator = SecretRandomGenerator::new(deterministic_seeder.seed());
        //~ TestResources {
            //~ seeder: deterministic_seeder,
            //~ encryption_random_generator,
            //~ secret_random_generator,
        //~ }
    //~ };

    //~ let f = |x: Scalar| x;

    //~ let delta: Scalar = encoding_with_padding / msg_modulus;
    //~ let mut msg = msg_modulus;

    //~ let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    //~ let mut noise_samples_fft = Vec::with_capacity(num_samples);
    //~ let mut noise_samples_kara = Vec::with_capacity(num_samples);

    //~ // generate pseudo-random secret
    //~ let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        //~ input_lwe_dimension,
        //~ &mut rsc.secret_random_generator,
    //~ );

    //~ // generate pseudo-random secret
    //~ let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        //~ glwe_dimension,
        //~ polynomial_size,
        //~ &mut rsc.secret_random_generator,
    //~ );

    //~ let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    //~ let (bsk, fbsk) = {
        //~ let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            //~ &input_lwe_secret_key,
            //~ &output_glwe_secret_key,
            //~ pbs_decomposition_base_log,
            //~ pbs_decomposition_level_count,
            //~ glwe_noise_distribution,
            //~ ciphertext_modulus,
            //~ &mut rsc.encryption_random_generator,
        //~ );

        //~ assert!(check_encrypted_content_respects_mod(
            //~ &*bsk,
            //~ ciphertext_modulus
        //~ ));

        //~ let mut fbsk = FourierLweBootstrapKey::new(
            //~ bsk.input_lwe_dimension(),
            //~ bsk.glwe_size(),
            //~ bsk.polynomial_size(),
            //~ bsk.decomposition_base_log(),
            //~ bsk.decomposition_level_count(),
        //~ );

        //~ par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

        //~ (bsk, fbsk)
    //~ };

    //~ let mut accumulator = generate_programmable_bootstrap_glwe_lut(
        //~ polynomial_size,
        //~ glwe_dimension.to_glwe_size(),
        //~ msg_modulus.cast_into(),
        //~ ciphertext_modulus,
        //~ delta,
        //~ f,
    //~ );

    //~ let reference_accumulator = accumulator.clone();

    //~ let ref_acc_plain = accumulator.get_body().as_ref().to_vec();

    //~ // noiseless GLWE encryption of LUT ... s.t. mask|body are random instead of zeros|plain-LUT
    //~ let zero_noise = Gaussian::from_dispersion_parameter(Variance(0.0), 0.0);
    //~ encrypt_glwe_ciphertext_assign(
        //~ &output_glwe_secret_key,
        //~ &mut accumulator,
        //~ zero_noise,
        //~ &mut rsc.encryption_random_generator,
    //~ );

    //~ let mut sanity_plain = PlaintextList::new(0, PlaintextCount(accumulator.polynomial_size().0));

    //~ decrypt_glwe_ciphertext(&output_glwe_secret_key, &accumulator, &mut sanity_plain);

    //~ let dec_sanity = sanity_plain.as_ref().to_vec();

    //~ assert_eq!(ref_acc_plain, dec_sanity);

    //~ assert!(check_encrypted_content_respects_mod(
        //~ &accumulator,
        //~ ciphertext_modulus
    //~ ));

    //~ while msg != Scalar::ZERO {
        //~ // msg = msg.wrapping_sub(Scalar::ONE);
        //~ msg = Scalar::ZERO;

        //~ println!("Acquiring {NB_TESTS} samples for \"{EXP_NAME}\" experiment ...");

        //~ let current_run_samples_kara_fft: Vec<_> = (0..NB_TESTS)
            //~ .into_par_iter()
            //~ .map(|thread_id| {
                //~ let mut rsc = TestResources::new();

                //~ let plaintext = Plaintext(msg * delta);

                //~ let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                    //~ &input_lwe_secret_key,
                    //~ plaintext,
                    //~ lwe_noise_distribution,
                    //~ ciphertext_modulus,
                    //~ &mut rsc.encryption_random_generator,
                //~ );

                //~ assert!(check_encrypted_content_respects_mod(
                    //~ &lwe_ciphertext_in,
                    //~ ciphertext_modulus
                //~ ));

                //~ let mut karatsuba_out_ct = LweCiphertext::new(
                    //~ Scalar::ZERO,
                    //~ output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    //~ ciphertext_modulus,
                //~ );

                //~ programmable_bootstrap_lwe_ciphertext(
                    //~ &lwe_ciphertext_in,
                    //~ &mut out_pbs_ct,
                    //~ &accumulator,
                    //~ &fbsk,
                //~ );

                //~ //TODO filename with gf=1

                //~ assert!(check_encrypted_content_respects_mod(
                    //~ &out_pbs_ct,
                    //~ ciphertext_modulus
                //~ ));

                //~ let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

                //~ let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                //~ assert_eq!(decoded, f(msg));

                //~ torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus)
            //~ })
            //~ .collect();

        //~ noise_samples.extend(current_run_samples);
    //~ }

    //~ let measured_variance = variance(&noise_samples);

    //~ let minimal_variance = minimal_lwe_variance_for_132_bits_security_gaussian(
        //~ fbsk.output_lwe_dimension(),
        //~ if ciphertext_modulus.is_native_modulus() {
            //~ 2.0f64.powi(Scalar::BITS as i32)
        //~ } else {
            //~ ciphertext_modulus.get_custom_modulus() as f64
        //~ },
    //~ );

    //~ // Have a log even if it's a test to have a trace in no capture mode to eyeball variances
    //~ println!("measured_variance={measured_variance:?}");
    //~ println!("expected_variance={expected_variance:?}");
    //~ println!("minimal_variance={minimal_variance:?}");

    //~ if measured_variance.0 < expected_variance.0 {
        //~ // We are in the clear as long as we have at least the noise for security
        //~ assert!(
            //~ measured_variance.0 >= minimal_variance.0,
            //~ "Found insecure variance after PBS\n\
            //~ measure_variance={measured_variance:?}\n\
            //~ minimal_variance={minimal_variance:?}"
        //~ );
    //~ } else {
        //~ // Check we are not too far from the expected variance if we are bigger
        //~ let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
        //~ let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;

        //~ assert!(
            //~ var_abs_diff < tolerance_threshold,
            //~ "Absolute difference for variance: {var_abs_diff}, \
            //~ tolerance threshold: {tolerance_threshold}, \
            //~ got variance: {measured_variance:?}, \
            //~ expected variance: {expected_variance:?}"
        //~ );
    //~ }
//~ }

//~ create_parametrized_test!(lwe_encrypt_pbs_decrypt_custom_mod {
    //~ NOISE_TEST_PARAMS_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN
//~ });
