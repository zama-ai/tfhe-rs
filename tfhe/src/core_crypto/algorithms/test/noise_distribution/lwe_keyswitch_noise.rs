use super::*;
use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::core_crypto::commons::test_tools::{normality_test_f64, torus_modular_diff, variance};
use crate::core_crypto::commons::traits::CastFrom;
use rayon::prelude::*;
use tfhe_noise_model::gaussian_noise::noise::keyswitch::variance_keyswitch;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 1000;

fn lwe_encrypt_ks_decrypt_noise_distribution_custom_mod<Scalar: UnsignedTorus + Send + Sync>(
    params: ClassicTestParams<Scalar>,
) where
    usize: CastFrom<Scalar>,
{
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let ciphertext_modulus_log = Scalar::BITS
        / usize::cast_from(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

    let expected_variance = Variance(
        variance_keyswitch(
            glwe_dimension
                .to_equivalent_lwe_dimension(polynomial_size)
                .0 as u64,
            ks_decomp_base_log.0 as u64,
            ks_decomp_level_count.0 as u64,
            ciphertext_modulus_log as u32,
            lwe_modular_std_dev.get_variance(),
        ) + glwe_modular_std_dev.get_variance(),
    );

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    const NORMALITY_RUNS: usize = 1000;
    let repeats = divide_ceil(
        NORMALITY_RUNS,
        <Scalar as CastInto<usize>>::cast_into(msg_modulus),
    );

    let res: Vec<_> = (0..repeats)
        .into_par_iter()
        .map(|repeat_count| {
            let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
            let mut std_dev_noise_samples = Vec::with_capacity(num_samples);
            let mut normality_noise_samples = Vec::with_capacity(1000);
            let mut msg = msg;

            while msg != Scalar::ZERO {
                msg = msg.wrapping_sub(Scalar::ONE);

                let mut rsc = TestResources::new();

                let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                    lwe_dimension,
                    &mut rsc.secret_random_generator,
                );

                let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                    glwe_dimension,
                    polynomial_size,
                    &mut rsc.secret_random_generator,
                );

                let big_lwe_sk = glwe_sk.into_lwe_secret_key();

                let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                    &big_lwe_sk,
                    &lwe_sk,
                    ks_decomp_base_log,
                    ks_decomp_level_count,
                    lwe_modular_std_dev,
                    ciphertext_modulus,
                    &mut rsc.encryption_random_generator,
                );

                assert!(check_encrypted_content_respects_mod(
                    &ksk_big_to_small,
                    ciphertext_modulus
                ));

                let current_noise_samples: Vec<_> = (0..NB_TESTS)
                    .into_par_iter()
                    .map(|_| {
                        let mut rsc = TestResources::new();

                        let plaintext = Plaintext(msg * delta);

                        let ct = allocate_and_encrypt_new_lwe_ciphertext(
                            &big_lwe_sk,
                            plaintext,
                            glwe_modular_std_dev,
                            ciphertext_modulus,
                            &mut rsc.encryption_random_generator,
                        );

                        assert!(check_encrypted_content_respects_mod(
                            &ct,
                            ciphertext_modulus
                        ));

                        let mut output_ct = LweCiphertext::new(
                            Scalar::ZERO,
                            lwe_sk.lwe_dimension().to_lwe_size(),
                            ciphertext_modulus,
                        );

                        keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);

                        assert!(check_encrypted_content_respects_mod(
                            &output_ct,
                            ciphertext_modulus
                        ));

                        let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

                        let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                        assert_eq!(msg, decoded);

                        let torus_diff =
                            torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
                        torus_diff
                    })
                    .collect();

                std_dev_noise_samples.extend(&current_noise_samples);
                normality_noise_samples.push(current_noise_samples);
            }
            println!("repeat {repeat_count} done");
            (std_dev_noise_samples, normality_noise_samples)
        })
        .collect();

    let (std_dev_noise_samples_sets, normality_noise_samples_sets): (Vec<_>, Vec<_>) =
        res.into_iter().unzip();
    let std_dev_noise_samples: Vec<_> = std_dev_noise_samples_sets.into_iter().flatten().collect();
    let normality_noise_samples_sets: Vec<Vec<f64>> =
        normality_noise_samples_sets.into_iter().flatten().collect();

    let measured_variance = variance(&std_dev_noise_samples);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;

    println!(
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );

    let failures = normality_noise_samples_sets
        .iter()
        .map(|normality_sample_set| {
            if normality_test_f64(normality_sample_set, 0.05).null_hypothesis_is_valid {
                0.0
            } else {
                1.0
            }
        })
        .sum::<f64>();

    let failure_rate = failures / normality_noise_samples_sets.len() as f64;

    println!("failure_rate={failure_rate}");

    assert!(failure_rate <= 0.065 * repeats as f64);
}

create_parametrized_test!(lwe_encrypt_ks_decrypt_noise_distribution_custom_mod);
