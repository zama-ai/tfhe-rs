use super::*;
use std::io::ErrorKind::Interrupted;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct StairKSParam<Scalar: UnsignedInteger> {
    pub log_precision: MessageModulusLog,
    /// This value is unused but allows to identify the parameter optimization that was done
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    // phi = number of coefficients != 0 in a given key for partial keys
    // this is the general phi for a GLWE secret key, which saturates to 2443 according to the
    // paper
    // phi == lwe_dimension + ks1_unshared_coeff_count + ks2_unshared_coeff_count
    pub partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount,
    pub bsk_glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub lwe_dimension: LweDimension,
    pub ks1_lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub ks2_lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_level: DecompositionLevelCount,
    pub pbs_base_log: DecompositionBaseLog,
    pub ks1_level: DecompositionLevelCount,
    pub ks1_base_log: DecompositionBaseLog,
    pub ks2_level: DecompositionLevelCount,
    pub ks2_base_log: DecompositionBaseLog,
    /// The number of elements being dropped when going from the large key to the inter key
    pub ks1_unshared_coeff_count: LweSecretKeyUnsharedCoefCount,
    /// The number of elements being dropped when going from the inter key to the small key
    pub ks2_unshared_coeff_count: LweSecretKeyUnsharedCoefCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

pub const PRECISION_4_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: MessageModulusLog(4),
    _log_mu: 4,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.16202663074765e-16,
    )),
    lwe_dimension: LweDimension(664),
    ks1_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.60713313301797e-9,
    )),
    ks2_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000380960250519291,
    )),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(22),
    ks1_level: DecompositionLevelCount(1),
    ks1_base_log: DecompositionBaseLog(13),
    ks2_level: DecompositionLevelCount(6),
    ks2_base_log: DecompositionBaseLog(2),
    ks1_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(922),
    ks2_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(462),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

fn lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod<
    Scalar: UnsignedTorus + Send + Sync + CastFrom<usize> + CastInto<usize>,
>(
    params: StairKSParam<Scalar>,
) {
    let StairKSParam {
        log_precision,
        _log_mu,
        glwe_dimension,
        polynomial_size,
        partial_glwe_secret_key_fill,
        bsk_glwe_noise_distribution,
        lwe_dimension,
        ks1_lwe_noise_distribution,
        ks2_lwe_noise_distribution,
        pbs_level,
        pbs_base_log,
        ks1_level,
        ks1_base_log,
        ks2_level,
        ks2_base_log,
        ks1_unshared_coeff_count,
        ks2_unshared_coeff_count,
        ciphertext_modulus,
    } = params;

    let msg_modulus = Scalar::ONE.shl(log_precision.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let large_lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    // Our algorithm is set up so that this equality holds, but in practice it could be more generic
    // if we had an intermediate LweDimension being defined
    assert_eq!(
        partial_glwe_secret_key_fill.0,
        lwe_dimension.0 + ks1_unshared_coeff_count.0 + ks2_unshared_coeff_count.0
    );

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        let glwe_secret_key = allocate_and_generate_new_partial_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            partial_glwe_secret_key_fill,
            &mut rsc.secret_random_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();
        let large_lwe_dimension_without_zeros = LweDimension(partial_glwe_secret_key_fill.0);

        let inter_lwe_dimension = LweDimension(
            large_lwe_dimension_without_zeros
                .shared_coef_count_from(ks1_unshared_coeff_count)
                .0,
        );
        let inter_lwe_secret_key = allocate_and_generate_fully_shared_binary_lwe_secret_key(
            &large_lwe_secret_key,
            inter_lwe_dimension,
        );

        let small_lwe_dimension = LweDimension(
            inter_lwe_secret_key
                .lwe_dimension()
                .shared_coef_count_from(ks2_unshared_coeff_count)
                .0,
        );
        let small_lwe_secret_key = allocate_and_generate_fully_shared_binary_lwe_secret_key(
            &inter_lwe_secret_key,
            small_lwe_dimension,
        );

        //Shrinking KSK generations
        let ksk_large_to_inter = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
            &large_lwe_secret_key,
            LweSecretKeySharedCoefCount(inter_lwe_dimension.0),
            ks1_base_log,
            ks1_level,
            ks1_lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &ksk_large_to_inter,
            ciphertext_modulus
        ));

        let ksk_inter_to_small = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
            &inter_lwe_secret_key,
            LweSecretKeySharedCoefCount(small_lwe_dimension.0),
            ks2_base_log,
            ks2_level,
            ks2_lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &ksk_inter_to_small,
            ciphertext_modulus
        ));

        //PBS PART
        let mut bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
            lwe_dimension,
            ciphertext_modulus,
        );

        par_generate_lwe_bootstrap_key(
            &small_lwe_secret_key,
            &glwe_secret_key,
            &mut bsk,
            bsk_glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let mut fbsk = FourierLweBootstrapKey::new(
            small_lwe_secret_key.lwe_dimension(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );

        convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);
        drop(bsk);

        let accumulator = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            msg_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            |x| x,
        );

        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            //Encryption
            let mut large_lwe = LweCiphertext::new(
                Scalar::ZERO,
                large_lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            encrypt_lwe_ciphertext(
                &large_lwe_secret_key,
                &mut large_lwe,
                plaintext,
                bsk_glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &large_lwe,
                ciphertext_modulus
            ));

            //Shrinking KS
            let mut inter_lwe = LweCiphertext::new(
                Scalar::ZERO,
                inter_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            let mut small_lwe = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let mut out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                large_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            // Check the AP works for several iterations
            for _ in 0..NB_TESTS {
                shrinking_keyswitch_lwe_ciphertext(&ksk_large_to_inter, &large_lwe, &mut inter_lwe);

                assert!(check_encrypted_content_respects_mod(
                    &inter_lwe,
                    ciphertext_modulus
                ));

                let dec_inter = decrypt_lwe_ciphertext(&inter_lwe_secret_key, &inter_lwe);
                let decoded = round_decode(dec_inter.0, delta) % msg_modulus;
                assert_eq!(decoded, msg, "Err after first shrinking KS");

                shrinking_keyswitch_lwe_ciphertext(&ksk_inter_to_small, &inter_lwe, &mut small_lwe);

                assert!(check_encrypted_content_respects_mod(
                    &small_lwe,
                    ciphertext_modulus
                ));

                let dec_small = decrypt_lwe_ciphertext(&small_lwe_secret_key, &small_lwe);
                let decoded = round_decode(dec_small.0, delta) % msg_modulus;
                assert_eq!(decoded, msg, "Err after second shrinking KS");

                programmable_bootstrap_lwe_ciphertext(
                    &small_lwe,
                    &mut out_pbs_ct,
                    &accumulator,
                    &fbsk,
                );

                assert!(check_encrypted_content_respects_mod(
                    &out_pbs_ct,
                    ciphertext_modulus
                ));

                let dec_large = decrypt_lwe_ciphertext(&large_lwe_secret_key, &out_pbs_ct);
                let decoded = round_decode(dec_large.0, delta) % msg_modulus;
                assert_eq!(decoded, msg, "Err after PBS");
            }
        }
    }
}

#[test]
fn lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_params_stair_4() {
    lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod(PRECISION_4_STAIR)
}

pub struct StairKSParamOneStepLY<Scalar: UnsignedInteger> {
    pub log_precision: MessageModulusLog,
    /// This value is unused but allows to identify the parameter optimization that was done
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount,
    pub bsk_glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub lwe_dimension: LweDimension,
    pub ks_lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_level: DecompositionLevelCount,
    pub pbs_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    /// The number of elements being dropped when going from the large key to the inter key
    pub ks_unshared_coeff_count: LweSecretKeyUnsharedCoefCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub log_extension_factor: u64,
}
pub const PRECISION_2_STAIR_ONE_STEP: StairKSParamOneStepLY<u64> = StairKSParamOneStepLY {
    log_precision: MessageModulusLog(2),
    _log_mu: 2,
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(3 * 512),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.390846778442423e-12,
    )),
    lwe_dimension: LweDimension(709),
    ks_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.0944272028597803e-05,
    )),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(827),
    ciphertext_modulus: CiphertextModulus::new_native(),
    log_extension_factor: 1,
};

pub const PRECISION_4_STAIR_ONE_STEP: StairKSParamOneStepLY<u64> = StairKSParamOneStepLY {
    log_precision: MessageModulusLog(4),
    _log_mu: 4,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.188173694010523e-16,
    )),
    lwe_dimension: LweDimension(790),
    ks_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.948683445911403e-06,
    )),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    ks_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(1258),
    ciphertext_modulus: CiphertextModulus::new_native(),
    log_extension_factor: 1,
};

pub const PRECISION_6_STAIR_ONE_STEP: StairKSParamOneStepLY<u64> = StairKSParamOneStepLY {
    log_precision: MessageModulusLog(6),
    _log_mu: 6,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.188173694010523e-16,
    )),
    lwe_dimension: LweDimension(853),
    ks_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6112135273032647e-06,
    )),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(15),
    ks_level: DecompositionLevelCount(8),
    ks_base_log: DecompositionBaseLog(2),
    ks_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(1195),
    ciphertext_modulus: CiphertextModulus::new_native(),
    log_extension_factor: 2,
};

pub const PRECISION_8_STAIR_ONE_STEP: StairKSParamOneStepLY<u64> = StairKSParamOneStepLY {
    log_precision: MessageModulusLog(8),
    _log_mu: 8,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.188173694010523e-16,
    )),
    lwe_dimension: LweDimension(925),
    ks_lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.468862725257972e-07,
    )),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(16),
    ks_level: DecompositionLevelCount(19),
    ks_base_log: DecompositionBaseLog(1),
    ks_unshared_coeff_count: LweSecretKeyUnsharedCoefCount(1123),
    ciphertext_modulus: CiphertextModulus::new_native(),
    log_extension_factor: 4,
};

fn lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_one_step<
    Scalar: UnsignedTorus + Send + Sync + CastFrom<usize> + CastInto<usize>,
>(
    params: StairKSParamOneStepLY<Scalar>,
) {
    let StairKSParamOneStepLY {
        log_precision,
        _log_mu,
        glwe_dimension,
        polynomial_size,
        partial_glwe_secret_key_fill,
        bsk_glwe_noise_distribution,
        lwe_dimension,
        ks_lwe_noise_distribution,
        pbs_level,
        pbs_base_log,
        ks_level,
        ks_base_log,
        ks_unshared_coeff_count,
        ciphertext_modulus,
        log_extension_factor,
    } = params;
    let shortcut_coeff_count = Ly23ShortcutCoeffCount(1);
    let extension_factor = Ly23ExtensionFactor(1 << log_extension_factor);
    let extended_polynomial_size = PolynomialSize(polynomial_size.0 * extension_factor.0);
    let msg_modulus = Scalar::ONE.shl(log_precision.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let large_lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    // Our algorithm is set up so that this equality holds, but in practice it could be more generic
    // if we had an intermediate LweDimension being defined
    assert_eq!(
        partial_glwe_secret_key_fill.0,
        lwe_dimension.0 + ks_unshared_coeff_count.0
    );

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);

        let glwe_secret_key = allocate_and_generate_new_partial_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            partial_glwe_secret_key_fill,
            &mut rsc.secret_random_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();
        let large_lwe_dimension_without_zeros = LweDimension(partial_glwe_secret_key_fill.0);

        let inter_lwe_dimension = LweDimension(
            large_lwe_dimension_without_zeros
                .shared_coef_count_from(ks_unshared_coeff_count)
                .0,
        );
        let inter_lwe_secret_key = allocate_and_generate_fully_shared_binary_lwe_secret_key(
            &large_lwe_secret_key,
            inter_lwe_dimension,
        );

        //Shrinking KSK generations
        let ksk_large_to_inter = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
            &large_lwe_secret_key,
            LweSecretKeySharedCoefCount(inter_lwe_dimension.0),
            ks_base_log,
            ks_level,
            ks_lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &ksk_large_to_inter,
            ciphertext_modulus
        ));

        //PBS PART
        let mut bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
            lwe_dimension,
            ciphertext_modulus,
        );

        par_generate_lwe_bootstrap_key(
            &inter_lwe_secret_key,
            &glwe_secret_key,
            &mut bsk,
            bsk_glwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        assert!(check_encrypted_content_respects_mod(
            &*bsk,
            ciphertext_modulus
        ));

        let mut fbsk = FourierLweBootstrapKey::new(
            inter_lwe_secret_key.lwe_dimension(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );

        convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);
        drop(bsk);

        let accumulator = generate_programmable_bootstrap_glwe_lut(
            extended_polynomial_size,
            glwe_dimension.to_glwe_size(),
            msg_modulus.cast_into(),
            ciphertext_modulus,
            delta,
            |x| x,
        );

        let mut buffers = ComputationBuffers::new();

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement_ly23::<u64>(
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                extension_factor,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            //Encryption
            let mut large_lwe = LweCiphertext::new(
                Scalar::ZERO,
                large_lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            encrypt_lwe_ciphertext(
                &large_lwe_secret_key,
                &mut large_lwe,
                plaintext,
                bsk_glwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &large_lwe,
                ciphertext_modulus
            ));

            //Shrinking KS
            let mut inter_lwe = LweCiphertext::new(
                Scalar::ZERO,
                inter_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            let mut out_pbs_ct = LweCiphertext::new(
                Scalar::ZERO,
                large_lwe_secret_key.lwe_dimension().to_lwe_size(),
                ciphertext_modulus,
            );

            // Check the AP works for several iterations
            for _ in 0..NB_TESTS {
                shrinking_keyswitch_lwe_ciphertext(&ksk_large_to_inter, &large_lwe, &mut inter_lwe);

                assert!(check_encrypted_content_respects_mod(
                    &inter_lwe,
                    ciphertext_modulus
                ));

                let dec_inter = decrypt_lwe_ciphertext(&inter_lwe_secret_key, &inter_lwe);
                let decoded = round_decode(dec_inter.0, delta) % msg_modulus;
                assert_eq!(decoded, msg, "Err after first shrinking KS");

                fbsk.as_view().bootstrap_bergerat24(
                    out_pbs_ct.as_mut_view(),
                    inter_lwe.as_view(),
                    accumulator.as_view(),
                    extension_factor,
                    shortcut_coeff_count,
                    fft,
                    buffers.stack(),
                );

                assert!(check_encrypted_content_respects_mod(
                    &out_pbs_ct,
                    ciphertext_modulus
                ));

                let dec_large = decrypt_lwe_ciphertext(&large_lwe_secret_key, &out_pbs_ct);
                let decoded = round_decode(dec_large.0, delta) % msg_modulus;
                assert_eq!(decoded, msg, "Err after PBS");
            }
        }
    }
}

#[test]
fn lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_params_stair_4_one_step() {
    lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_one_step(PRECISION_2_STAIR_ONE_STEP);
    println!("2ok");
    lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_one_step(PRECISION_4_STAIR_ONE_STEP);
    println!("4ok");
    lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_one_step(PRECISION_6_STAIR_ONE_STEP);
    println!("6ok");
    lwe_encrypt_stair_keyswitch_pbs_decrypt_custom_mod_one_step(PRECISION_8_STAIR_ONE_STEP);
    println!("8ok");
}
