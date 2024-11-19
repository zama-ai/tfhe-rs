use super::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

fn lwe_encrypt_pbs_128_decrypt_custom_mod(params: ClassicTestParams<u128>) {
    type Scalar = u128;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glew_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE << (message_modulus_log.0);
    let input_lwe_dimension = params.lwe_dimension;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomposition_base_log = params.pbs_base_log;
    let decomposition_level_count = params.pbs_level;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| x;

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_encrypted_content_respects_mod(
        &accumulator,
        ciphertext_modulus
    ));

    let input_lwe_secret_key =
        LweSecretKey::generate_new_binary(input_lwe_dimension, &mut rsc.secret_random_generator);
    let output_glwe_secret_key = GlweSecretKey::generate_new_binary(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.as_lwe_secret_key();

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        decomposition_base_log,
        decomposition_level_count,
        glew_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let mut ntt_bsk = CrtNtt128LweBsk::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomposition_base_log,
        decomposition_level_count,
        ciphertext_modulus,
    );

    convert_standard_lwe_bootstrap_key_to_crt_ntt_128(&bsk, &mut ntt_bsk);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        for _ in 0..NB_TESTS {
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

            let mut out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            let start = std::time::Instant::now();

            pbs_ntt_128(&lwe_ciphertext_in, &mut out_pbs_ct, &accumulator, &ntt_bsk);
            let elapsed = start.elapsed();

            println!("elapsed={elapsed:?}");

            assert!(check_encrypted_content_respects_mod(
                &out_pbs_ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }

        // In coverage, we break after one while loop iteration, changing message values does not
        // yield higher coverage
        #[cfg(tarpaulin)]
        break;
    }
}

pub const TEST_PARAMS_4_BITS_NATIVE_U128: ClassicTestParams<u128> = ClassicTestParams {
    lwe_dimension: LweDimension(880),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
    pbs_base_log: DecompositionBaseLog(32),
    pbs_level: DecompositionLevelCount(3),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

create_parametrized_test!(lwe_encrypt_pbs_128_decrypt_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U128
});
