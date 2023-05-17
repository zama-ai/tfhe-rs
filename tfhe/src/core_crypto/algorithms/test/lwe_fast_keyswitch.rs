use super::*;
use crate::core_crypto::algorithms::test::MessageModulusLog;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FastKSParam<Scalar: UnsignedInteger> {
    pub log_precision: MessageModulusLog,
    /// This value is unused but allows to identify the parameter optimization that was done
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    // phi_bsk = number of coefficients != 0 in a given key for partial keys
    // this is the general phi_bsk for a GLWE secret key, which saturates to 2443 according to the
    // paper
    pub bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount,
    pub bsk_glwe_std_dev: StandardDev,
    pub lwe_dimension: LweDimension,
    pub ks1_lwe_modular_std_dev: StandardDev,
    pub pbs_level: DecompositionLevelCount,
    pub pbs_base_log: DecompositionBaseLog,
    pub ks1_level: DecompositionLevelCount,
    pub ks1_base_log: DecompositionBaseLog,
    pub ks1_polynomial_size: PolynomialSize,
    pub ks_in_glwe_dimension: GlweDimension,
    pub phi_in: usize,
    pub ks_out_glwe_dimension: GlweDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

#[allow(dead_code)]
pub const PRECISION_1_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(1),
    _log_mu: 1,
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(1280),
    bsk_glwe_std_dev: StandardDev(4.436066365074074e-10),
    lwe_dimension: LweDimension(534),
    ks1_lwe_modular_std_dev: StandardDev(0.0004192214045106218),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(15),
    ks1_level: DecompositionLevelCount(9),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(256),
    ks_in_glwe_dimension: GlweDimension(3),
    phi_in: 746,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_2_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(2),
    _log_mu: 2,
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(1536),
    bsk_glwe_std_dev: StandardDev(3.953518398797519e-12),
    lwe_dimension: LweDimension(590),
    ks1_lwe_modular_std_dev: StandardDev(0.0001492480807729575),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks1_level: DecompositionLevelCount(11),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(1024),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 946,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_3_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(3),
    _log_mu: 3,
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(1536),
    bsk_glwe_std_dev: StandardDev(3.953518398797519e-12),
    lwe_dimension: LweDimension(686),
    ks1_lwe_modular_std_dev: StandardDev(2.5308824029981747e-5),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks1_level: DecompositionLevelCount(13),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(1024),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 850,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_4_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(4),
    _log_mu: 4,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_std_dev: StandardDev(3.162026630747649e-16),
    lwe_dimension: LweDimension(682),
    ks1_lwe_modular_std_dev: StandardDev(2.7313997525878062e-5),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(14),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(512),
    ks_in_glwe_dimension: GlweDimension(3), // Original value
    // ks_in_glwe_dimension: GlweDimension(4), // Test non square pseudo GGSWs
    phi_in: 1366,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_5_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(5),
    _log_mu: 5,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_std_dev: StandardDev(3.162026630747649e-16),
    lwe_dimension: LweDimension(766),
    ks1_lwe_modular_std_dev: StandardDev(5.822216831056818e-06),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(15),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(512),
    ks_in_glwe_dimension: GlweDimension(3),
    phi_in: 1282,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_6_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(6),
    _log_mu: 6,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(774),
    ks1_lwe_modular_std_dev: StandardDev(4.998754134591537e-06),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(14),
    ks1_level: DecompositionLevelCount(15),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(2048),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 1669,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_7_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(7),
    _log_mu: 7,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(818),
    ks1_lwe_modular_std_dev: StandardDev(2.2215530137414073e-06),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(14),
    ks1_level: DecompositionLevelCount(16),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(2048),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 1625,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_8_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(8),
    _log_mu: 8,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(854),
    ks1_lwe_modular_std_dev: StandardDev(1.1499479557902908e-06),
    pbs_level: DecompositionLevelCount(3),
    pbs_base_log: DecompositionBaseLog(11),
    ks1_level: DecompositionLevelCount(18),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(2048),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 1589,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_9_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(9),
    _log_mu: 9,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(902),
    ks1_lwe_modular_std_dev: StandardDev(4.7354340335704556e-07),
    pbs_level: DecompositionLevelCount(4),
    pbs_base_log: DecompositionBaseLog(8),
    ks1_level: DecompositionLevelCount(18),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(2048),
    ks_in_glwe_dimension: GlweDimension(1),
    phi_in: 1541,
    ks_out_glwe_dimension: GlweDimension(1),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_10_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(10),
    _log_mu: 10,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(938),
    ks1_lwe_modular_std_dev: StandardDev(2.434282602565751e-07),
    pbs_level: DecompositionLevelCount(6),
    pbs_base_log: DecompositionBaseLog(6),
    ks1_level: DecompositionLevelCount(20),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(512),
    ks_in_glwe_dimension: GlweDimension(3),
    phi_in: 1505,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
#[allow(dead_code)]
pub const PRECISION_11_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision:  MessageModulusLog(11),
    _log_mu: 11,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2443),
    bsk_glwe_std_dev: StandardDev(2.168404344971009e-19),
    lwe_dimension: LweDimension(1018),
    ks1_lwe_modular_std_dev: StandardDev(5.56131000242714e-08),
    pbs_level: DecompositionLevelCount(13),
    pbs_base_log: DecompositionBaseLog(3),
    ks1_level: DecompositionLevelCount(22),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(512),
    ks_in_glwe_dimension: GlweDimension(3),
    phi_in: 1425,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};


fn lwe_encrypt_fast_ks_decrypt_custom_mod<
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize> + Sync + Send,
>(
    params: FastKSParam<Scalar>,
) {
    let log_precision = params.log_precision;
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let bsk_partial_glwe_secret_key_fill = params.bsk_partial_glwe_secret_key_fill;
    let bsk_glwe_std_dev = params.bsk_glwe_std_dev;
    let lwe_dimension = params.lwe_dimension;
    let ks1_lwe_modular_std_dev = params.ks1_lwe_modular_std_dev;
    let pbs_level = params.pbs_level;
    let pbs_base_log = params.pbs_base_log;
    let ks1_level = params.ks1_level;
    let ks1_base_log = params.ks1_base_log;
    let ks1_polynomial_size = params.ks1_polynomial_size;
    let ks_in_glwe_dimension = params.ks_in_glwe_dimension;
    let phi_in = params.phi_in;
    let ks_out_glwe_dimension = params.ks_out_glwe_dimension;
    let ciphertext_modulus = params.ciphertext_modulus;

    let msg_modulus = Scalar::ONE.shl(log_precision.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let f = |x| x;

    // Shared and partial key generations
    let glwe_secret_key = allocate_and_generate_new_binary_partial_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        bsk_partial_glwe_secret_key_fill,
        &mut rsc.secret_random_generator,
    );

    let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

    // Shared small lwe secret key sharing lwe_dimension coeffs with the glwe_secret_key
    let mut small_lwe_secret_key = LweSecretKey::new_empty_key(Scalar::ZERO, lwe_dimension);
    small_lwe_secret_key.as_mut()[0..lwe_dimension.0]
        .copy_from_slice(&glwe_secret_key.as_ref()[0..lwe_dimension.0]);

    // Corresponds to the small LWE sk with only lwe_dimension coeffs that are non zero and
    // shared with the glwe_secret_key
    let small_glwe_secret_key =
        allocate_and_generate_new_shared_glwe_secret_key_from_glwe_secret_key(
            &glwe_secret_key,
            ks_out_glwe_dimension,
            lwe_dimension.0,
            ks1_polynomial_size,
        );

    let mut large_glwe_secret_key_unshared =
        GlweSecretKey::new_empty_key(Scalar::ZERO, ks_in_glwe_dimension, ks1_polynomial_size);

    // Get the unshared coefficients in the large glwe secret key which is used for the input of
    // the KS
    large_glwe_secret_key_unshared.as_mut()
        [0..bsk_partial_glwe_secret_key_fill.0 - lwe_dimension.0]
        .copy_from_slice(
            &glwe_secret_key.as_ref()[lwe_dimension.0..bsk_partial_glwe_secret_key_fill.0],
        );

    //Memory stuff
    let fft_ks = Fft::new(ks1_polynomial_size);
    let fft_ks = fft_ks.as_view();
    let mut ks_buffers = ComputationBuffers::new();
    let mut pbs_buffers = ComputationBuffers::new();

    let fft_pbs = Fft::new(polynomial_size);
    let fft_pbs = fft_pbs.as_view();

    let ks_buffer_size_req =
        add_external_product_fast_keyswitch_assign_mem_optimized_requirement::<Scalar>(
            small_glwe_secret_key.glwe_dimension(),
            ks1_polynomial_size,
            fft_ks,
        )
        .unwrap()
        .try_unaligned_bytes_required()
        .unwrap();

    let ks_buffer_size_req = ks_buffer_size_req.max(
        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft_ks)
            .unwrap()
            .unaligned_bytes_required(),
    );
    let pbs_buffer_size_req = programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<
        Scalar,
    >(glwe_dimension.to_glwe_size(), polynomial_size, fft_pbs)
    .unwrap()
    .try_unaligned_bytes_required()
    .unwrap();

    ks_buffers.resize(ks_buffer_size_req);
    pbs_buffers.resize(pbs_buffer_size_req);

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
        bsk_glwe_std_dev,
        &mut rsc.encryption_random_generator,
    );

    let mut fbsk = FourierLweBootstrapKey::new(
        small_lwe_secret_key.lwe_dimension(),
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
    );

    convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
        &bsk,
        &mut fbsk,
        fft_pbs,
        pbs_buffers.stack(),
    );

    drop(bsk);

    let accumulator = generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    let mut ggsw = PseudoGgswCiphertext::new(
        Scalar::ZERO,
        ks_in_glwe_dimension.to_glwe_size(),
        ks_out_glwe_dimension.to_glwe_size(),
        ks1_polynomial_size,
        ks1_base_log,
        ks1_level,
        ciphertext_modulus,
    );

    encrypt_pseudo_ggsw_ciphertext(
        &small_glwe_secret_key,
        &large_glwe_secret_key_unshared,
        &mut ggsw,
        ks1_lwe_modular_std_dev,
        &mut rsc.encryption_random_generator,
    );

    //To Fourier
    let mut fourier_ggsw = PseudoFourierGgswCiphertext::new(
        ks_in_glwe_dimension.to_glwe_size(),
        ks_out_glwe_dimension.to_glwe_size(),
        ks1_polynomial_size,
        ks1_base_log,
        ks1_level,
    );

    convert_standard_pseudo_ggsw_ciphertext_to_fourier_mem_optimized(
        &ggsw,
        &mut fourier_ggsw,
        fft_ks,
        ks_buffers.stack(),
    );

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        println!("msg={msg}");

        for test_iteration in 0..NB_TESTS {
            println!("test_iteration={test_iteration}");
            let plaintext = Plaintext(msg * delta);

            let mut large_lwe_ciphertext_ap_input = allocate_and_encrypt_new_lwe_ciphertext(
                &large_lwe_secret_key,
                plaintext,
                bsk_glwe_std_dev,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut large_lwe_shared_part = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let mut large_lwe_unshared_part_requires_keyswitch = LweCiphertext::new(
                Scalar::ZERO,
                LweSize(bsk_partial_glwe_secret_key_fill.0 - lwe_dimension.0 + 1),
                ciphertext_modulus,
            );

            let mut large_glwe_unshared_requires_keyswitch = GlweCiphertext::new(
                Scalar::ZERO,
                ks_in_glwe_dimension.to_glwe_size(),
                ks1_polynomial_size,
                ciphertext_modulus,
            );

            let mut glwe_unshared_after_ks = GlweCiphertext::new(
                Scalar::ZERO,
                ks_out_glwe_dimension.to_glwe_size(),
                ks1_polynomial_size,
                ciphertext_modulus,
            );

            let mut small_lwe_unshared_after_ks = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            // Check the AP works for several iterations
            for ap_iteration in 0..NB_TESTS {
                println!("ap_iteration={ap_iteration}");
                let decrypted =
                    decrypt_lwe_ciphertext(&large_lwe_secret_key, &large_lwe_ciphertext_ap_input);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                // Copy the shared part in the smaller ciphertext
                large_lwe_shared_part
                    .get_mut_mask()
                    .as_mut()
                    .copy_from_slice(
                        &large_lwe_ciphertext_ap_input.get_mask().as_ref()[..lwe_dimension.0],
                    );
                *large_lwe_shared_part.get_mut_body().data =
                    *large_lwe_ciphertext_ap_input.get_body().data;

                // Copy the unshared part to be keyswitched
                large_lwe_unshared_part_requires_keyswitch
                    .get_mut_mask()
                    .as_mut()
                    .copy_from_slice(
                        &large_lwe_ciphertext_ap_input.get_mask().as_ref()
                            [lwe_dimension.0..bsk_partial_glwe_secret_key_fill.0],
                    );

                partial_convert_lwe_ciphertext_into_constant_glwe_ciphertext(
                    &large_lwe_unshared_part_requires_keyswitch,
                    &mut large_glwe_unshared_requires_keyswitch,
                    phi_in,
                );

                glwe_unshared_after_ks.as_mut().fill(Scalar::ZERO);

                add_external_product_fast_keyswitch_assign_mem_optimized(
                    &mut glwe_unshared_after_ks,
                    &fourier_ggsw,
                    &large_glwe_unshared_requires_keyswitch,
                    fft_ks,
                    ks_buffers.stack(),
                );

                partial_extract_lwe_sample_from_glwe_ciphertext(
                    &glwe_unshared_after_ks,
                    &mut small_lwe_unshared_after_ks,
                    MonomialDegree(0),
                    lwe_dimension.0,
                );

                // Sum with initial ct's shared part
                small_lwe_unshared_after_ks
                    .get_mut_mask()
                    .as_mut()
                    .iter_mut()
                    .zip(large_lwe_shared_part.as_ref()[0..lwe_dimension.0].iter())
                    .for_each(|(dst, &src)| *dst = dst.wrapping_add(src));
                // Sum the body
                let body = small_lwe_unshared_after_ks.get_mut_body().data;
                *body = (*body).wrapping_add(*large_lwe_shared_part.get_body().data);

                let decrypted =
                    decrypt_lwe_ciphertext(&small_lwe_secret_key, &small_lwe_unshared_after_ks);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    &small_lwe_unshared_after_ks,
                    &mut large_lwe_ciphertext_ap_input,
                    &accumulator,
                    &fbsk,
                    fft_pbs,
                    pbs_buffers.stack(),
                );

                let decrypted =
                    decrypt_lwe_ciphertext(&large_lwe_secret_key, &large_lwe_ciphertext_ap_input);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(decoded, f(msg));

                ////////////
                // Remove the input message to get 0
                lwe_ciphertext_plaintext_sub_assign(&mut large_lwe_ciphertext_ap_input, plaintext);

                let decrypted =
                    decrypt_lwe_ciphertext(&large_lwe_secret_key, &large_lwe_ciphertext_ap_input);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(Scalar::ZERO, decoded, "Error after sub");
                ////////////

                // multiply by a cleartext, will still output 0 but is the biggest noise growth
                // possible
                lwe_ciphertext_cleartext_mul_assign(
                    &mut large_lwe_ciphertext_ap_input,
                    Cleartext(msg_modulus),
                );
                let decrypted =
                    decrypt_lwe_ciphertext(&large_lwe_secret_key, &large_lwe_ciphertext_ap_input);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;
                assert_eq!(Scalar::ZERO, decoded, "Error after mul");
                ////////////

                // Add back the input plaintext to still be doing an overall identity computation
                lwe_ciphertext_plaintext_add_assign(&mut large_lwe_ciphertext_ap_input, plaintext);
                let decrypted =
                    decrypt_lwe_ciphertext(&large_lwe_secret_key, &large_lwe_ciphertext_ap_input);

                let decoded = round_decode(decrypted.0, delta) % msg_modulus;
                assert_eq!(msg, decoded, "Error after add");
                ////////////
            }
        }
    }
}

create_parametrized_test!(lwe_encrypt_fast_ks_decrypt_custom_mod {
    PRECISION_1_FAST_KS,
    PRECISION_2_FAST_KS,
    PRECISION_3_FAST_KS,
    PRECISION_4_FAST_KS,
    PRECISION_5_FAST_KS,
    PRECISION_6_FAST_KS
    // PRECISION_7_FAST_KS,
    // PRECISION_8_FAST_KS
    // PRECISION_9_FAST_KS,
    // PRECISION_10_FAST_KS,
    // PRECISION_11_FAST_KS
});
