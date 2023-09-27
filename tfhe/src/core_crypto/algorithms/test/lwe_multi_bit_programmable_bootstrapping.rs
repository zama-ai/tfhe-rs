use super::*;

#[cfg(not(feature = "__coverage"))]
const NB_TESTS: usize = 10;
#[cfg(not(feature = "__coverage"))]
// Divided by two compared to other tests, we are running the algorithm twice for determinism
const NB_TESTS_LIGHT: usize = 5;
#[cfg(feature = "__coverage")]
const NB_TESTS: usize = 1;
#[cfg(feature = "__coverage")]
const NB_TESTS_LIGHT: usize = 1;

pub struct MultiBitParams<Scalar: UnsignedInteger> {
    pub input_lwe_dimension: LweDimension,
    pub lwe_modular_std_dev: StandardDev,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_modular_std_dev: StandardDev,
    pub message_modulus_log: CiphertextModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub grouping_factor: LweBskGroupingFactor,
    pub thread_count: ThreadCount,
}

fn lwe_encrypt_multi_bit_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: MultiBitParams<Scalar>,
) {
    let input_lwe_dimension = params.input_lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.decomp_base_log;
    let decomp_level_count = params.decomp_level_count;
    let grouping_factor = params.grouping_factor;
    let thread_count = params.thread_count;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_content_respects_mod(&accumulator, ciphertext_modulus));

    // Keygen is a bit slow on this one so we keep it out of the testing loop
    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweMultiBitBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_content_respects_mod(&*bsk, ciphertext_modulus));

    let mut fbsk = FourierLweMultiBitBootstrapKey::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        grouping_factor,
    );

    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    drop(bsk);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let mut out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            multi_bit_programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &fbsk,
                thread_count,
            );

            assert!(check_content_respects_mod(&out_pbs_ct, ciphertext_modulus));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

fn lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: MultiBitParams<Scalar>,
) {
    let input_lwe_dimension = params.input_lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.decomp_base_log;
    let decomp_level_count = params.decomp_level_count;
    let grouping_factor = params.grouping_factor;
    let thread_count = params.thread_count;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_content_respects_mod(&accumulator, ciphertext_modulus));

    // Keygen is a bit slow on this one so we keep it out of the testing loop
    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweMultiBitBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_content_respects_mod(&*bsk, ciphertext_modulus));

    let mut fbsk = FourierLweMultiBitBootstrapKey::new(
        input_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        grouping_factor,
    );

    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    drop(bsk);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS_LIGHT {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let out_pbs_ct = {
                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator,
                    &fbsk,
                    thread_count,
                );

                assert!(check_content_respects_mod(&out_pbs_ct, ciphertext_modulus));

                let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                out_pbs_ct
            };

            let out_pbs_ct_other = {
                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator,
                    &fbsk,
                    thread_count,
                );

                out_pbs_ct
            };

            assert_eq!(out_pbs_ct_other, out_pbs_ct);
        }
    }
}

fn lwe_encrypt_std_multi_bit_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: MultiBitParams<Scalar>,
) {
    let input_lwe_dimension = params.input_lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.decomp_base_log;
    let decomp_level_count = params.decomp_level_count;
    let grouping_factor = params.grouping_factor;
    let thread_count = params.thread_count;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_content_respects_mod(&accumulator, ciphertext_modulus));

    // Keygen is a bit slow on this one so we keep it out of the testing loop
    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweMultiBitBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_content_respects_mod(&*bsk, ciphertext_modulus));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let mut out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            std_multi_bit_programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_in,
                &mut out_pbs_ct,
                &accumulator,
                &bsk,
                thread_count,
            );

            assert!(check_content_respects_mod(&out_pbs_ct, ciphertext_modulus));

            let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(decoded, f(msg));
        }
    }
}

fn std_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize>,
>(
    params: MultiBitParams<Scalar>,
) {
    let input_lwe_dimension = params.input_lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let decomp_base_log = params.decomp_base_log;
    let decomp_level_count = params.decomp_level_count;
    let grouping_factor = params.grouping_factor;
    let thread_count = params.thread_count;

    let mut rsc = TestResources::new();

    let f = |x: Scalar| {
        x.wrapping_mul(Scalar::TWO)
            .wrapping_sub(Scalar::ONE)
            .wrapping_rem(msg_modulus)
    };

    let delta: Scalar = encoding_with_padding / msg_modulus;
    let mut msg = msg_modulus;

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    assert!(check_content_respects_mod(&accumulator, ciphertext_modulus));

    // Keygen is a bit slow on this one so we keep it out of the testing loop
    // Create the LweSecretKey
    let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        input_lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweMultiBitBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        grouping_factor,
        ciphertext_modulus,
    );

    par_generate_lwe_multi_bit_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    assert!(check_content_respects_mod(&*bsk, ciphertext_modulus));

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS_LIGHT {
            let plaintext = Plaintext(msg * delta);

            let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                &input_lwe_secret_key,
                plaintext,
                lwe_modular_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(
                &lwe_ciphertext_in,
                ciphertext_modulus
            ));

            let out_pbs_ct = {
                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                std_multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator,
                    &bsk,
                    thread_count,
                );

                assert!(check_content_respects_mod(&out_pbs_ct, ciphertext_modulus));

                let decrypted = decrypt_lwe_ciphertext(&output_lwe_secret_key, &out_pbs_ct);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                out_pbs_ct
            };

            let out_pbs_ct_other = {
                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );

                std_multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                    &lwe_ciphertext_in,
                    &mut out_pbs_ct,
                    &accumulator,
                    &bsk,
                    thread_count,
                );

                out_pbs_ct
            };

            assert_eq!(out_pbs_ct_other, out_pbs_ct);
        }
    }
}

// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield
// correct computations
const MULTI_BIT_2_2_2_PARAMS: MultiBitParams<u64> = MultiBitParams {
    input_lwe_dimension: LweDimension(818),
    lwe_modular_std_dev: StandardDev(0.000002226459789930014),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(5),
};

const MULTI_BIT_2_2_3_PARAMS: MultiBitParams<u64> = MultiBitParams {
    input_lwe_dimension: LweDimension(888),
    lwe_modular_std_dev: StandardDev(0.0000006125031601933181),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_modular_std_dev: StandardDev(0.0000000000000003152931493498455),
    message_modulus_log: CiphertextModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[test]
pub fn test_lwe_encrypt_multi_bit_pbs_decrypt_factor_2_thread_5_native_mod() {
    lwe_encrypt_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_pbs_decrypt_factor_3_thread_12_native_mod() {
    lwe_encrypt_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_pbs_decrypt_factor_2_thread_5_custom_mod() {
    lwe_encrypt_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_pbs_decrypt_factor_3_thread_12_custom_mod() {
    lwe_encrypt_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_2_thread_5_native_mod() {
    lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_3_thread_12_native_mod() {
    lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_2_thread_5_custom_mod() {
    lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_3_thread_12_custom_mod() {
    lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_std_multi_bit_pbs_decrypt_factor_2_thread_5_native_mod() {
    lwe_encrypt_std_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_std_multi_bit_pbs_decrypt_factor_3_thread_12_native_mod() {
    lwe_encrypt_std_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_std_multi_bit_pbs_decrypt_factor_2_thread_5_custom_mod() {
    lwe_encrypt_std_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn test_lwe_encrypt_std_multi_bit_pbs_decrypt_factor_3_thread_12_custom_mod() {
    lwe_encrypt_std_multi_bit_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn std_test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_2_thread_5_native_mod() {
    std_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn std_test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_3_thread_12_native_mod() {
    std_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}

#[test]
pub fn std_test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_2_thread_5_custom_mod() {
    std_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(5),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_2_PARAMS
    });
}

#[test]
pub fn std_test_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_factor_3_thread_12_custom_mod() {
    std_lwe_encrypt_multi_bit_deterministic_pbs_decrypt_custom_mod::<u64>(MultiBitParams {
        thread_count: ThreadCount(12),
        message_modulus_log: CiphertextModulusLog(3),
        ciphertext_modulus: CiphertextModulus::try_new_power_of_2(63).unwrap(),
        ..MULTI_BIT_2_2_3_PARAMS
    });
}
