use super::*;

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
    pub bsk_glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub lwe_dimension: LweDimension,
    pub ks1_lwe_modular_noise_distribution: DynamicDistribution<Scalar>,
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

/// This is the original precision 5 parameters tweaked to use for 4 bits, such that the pfail is
/// much lower than 2^-14, it should be approximately ~2^-49
pub const PRECISION_4_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: MessageModulusLog(4), // original: log_precision: 5,
    _log_mu: 5,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    bsk_partial_glwe_secret_key_fill: PartialGlweSecretKeyRandomCoefCount(2048),
    bsk_glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.162026630747649e-16,
    )),
    lwe_dimension: LweDimension(766),
    ks1_lwe_modular_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
        StandardDev(5.822_216_831_056_818e-6),
    ),
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

// AP:
// DP -> Fast KS -> PBS
// Fast KS =
// - convert LWE to GLWE without packing called "sample insertion"
// - GLWE fast KS
// - sample extraction
// - finalize the keyswitch
// Here we skip the DP for now as we don't have 2^-40 parameters for the fast KS at the moment
fn lwe_encrypt_fast_ks_decrypt_custom_mod<
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize> + Sync + Send,
>(
    params: FastKSParam<Scalar>,
) {
    let FastKSParam {
        log_precision,
        _log_mu,
        glwe_dimension,
        polynomial_size,
        bsk_partial_glwe_secret_key_fill,
        bsk_glwe_noise_distribution,
        lwe_dimension,
        ks1_lwe_modular_noise_distribution,
        pbs_level,
        pbs_base_log,
        ks1_level,
        ks1_base_log,
        ks1_polynomial_size,
        ks_in_glwe_dimension,
        phi_in,
        ks_out_glwe_dimension,
        ciphertext_modulus,
    } = params;

    let msg_modulus = Scalar::ONE.shl(log_precision.0);
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let f = |x| x;

    // Shared and partial key generations
    let glwe_secret_key = allocate_and_generate_new_partial_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        bsk_partial_glwe_secret_key_fill,
        &mut rsc.secret_random_generator,
    );

    let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

    // Shared small lwe secret key sharing lwe_dimension coeffs with the glwe_secret_key
    let small_lwe_secret_key = allocate_and_generate_fully_shared_binary_lwe_secret_key(
        &glwe_secret_key.as_lwe_secret_key(),
        lwe_dimension,
    );

    // Corresponds to the small LWE sk with only lwe_dimension coeffs that are non zero and
    // shared with the glwe_secret_key
    let small_glwe_secret_key =
        allocate_and_generate_new_shared_glwe_secret_key_from_glwe_secret_key(
            &glwe_secret_key,
            ks_out_glwe_dimension,
            GlweSecretKeySharedCoefCount(lwe_dimension.0),
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

    let ks_buffer_size_req = glwe_fast_keyswitch_requirement::<Scalar>(
        small_glwe_secret_key.glwe_dimension().to_glwe_size(),
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
        bsk_glwe_noise_distribution,
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

    let accumulator = generate_programmable_bootstrap_glwe_lut(
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
        ks1_lwe_modular_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    // To Fourier
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

        for _ in 0..NB_TESTS {
            let plaintext = Plaintext(msg * delta);

            let mut large_lwe_ciphertext_ap_input = allocate_and_encrypt_new_lwe_ciphertext(
                &large_lwe_secret_key,
                plaintext,
                bsk_glwe_noise_distribution,
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

            glwe_fast_keyswitch(
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
        }
    }
}

create_parameterized_test!(lwe_encrypt_fast_ks_decrypt_custom_mod {
    PRECISION_4_FAST_KS
});
