#![allow(clippy::excessive_precision)]
use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;
use tfhe::named_params_impl;

fn generate_accumulator<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
}

named_params_impl!(
    FastKSParam<u64> =>
    PRECISION_1_FAST_KS,
    PRECISION_2_FAST_KS,
    PRECISION_3_FAST_KS,
    PRECISION_4_FAST_KS,
    PRECISION_5_FAST_KS,
    PRECISION_6_FAST_KS,
    PRECISION_7_FAST_KS,
    PRECISION_8_FAST_KS,
    PRECISION_9_FAST_KS,
    PRECISION_10_FAST_KS,
    PRECISION_11_FAST_KS
);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FastKSParam<Scalar: UnsignedTorus> {
    pub log_precision: usize,
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub phi_bsk: usize,
    pub std_dev_bsk: StandardDev,
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

pub const PRECISION_1_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 1,
    _log_mu: 1,
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    phi_bsk: 1280,
    std_dev_bsk: StandardDev(4.436066365074074e-10),
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
pub const PRECISION_2_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 2,
    _log_mu: 2,
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    phi_bsk: 1536,
    std_dev_bsk: StandardDev(3.953518398797519e-12),
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
pub const PRECISION_3_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 3,
    _log_mu: 3,
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    phi_bsk: 1536,
    std_dev_bsk: StandardDev(3.953518398797519e-12),
    lwe_dimension: LweDimension(686),
    ks1_lwe_modular_std_dev: StandardDev(2.5308824029981747e-05),
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
pub const PRECISION_4_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 4,
    _log_mu: 4,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    phi_bsk: 2048,
    std_dev_bsk: StandardDev(3.162026630747649e-16),
    lwe_dimension: LweDimension(682),
    ks1_lwe_modular_std_dev: StandardDev(2.7313997525878062e-05),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(14),
    ks1_base_log: DecompositionBaseLog(1),
    ks1_polynomial_size: PolynomialSize(512),
    ks_in_glwe_dimension: GlweDimension(3),
    phi_in: 1366,
    ks_out_glwe_dimension: GlweDimension(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};
pub const PRECISION_5_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 5,
    _log_mu: 5,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    phi_bsk: 2048,
    std_dev_bsk: StandardDev(3.162026630747649e-16),
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
pub const PRECISION_6_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 6,
    _log_mu: 6,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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
pub const PRECISION_7_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 7,
    _log_mu: 7,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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
pub const PRECISION_8_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 8,
    _log_mu: 8,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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
pub const PRECISION_9_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 9,
    _log_mu: 9,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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
pub const PRECISION_10_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 10,
    _log_mu: 10,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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
pub const PRECISION_11_FAST_KS: FastKSParam<u64> = FastKSParam {
    log_precision: 11,
    _log_mu: 11,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    phi_bsk: 2443,
    std_dev_bsk: StandardDev(2.168404344971009e-19),
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

fn criterion_bench(c: &mut Criterion) {
    let param_vec = [
        PRECISION_1_FAST_KS,
        PRECISION_2_FAST_KS,
        PRECISION_3_FAST_KS,
        PRECISION_4_FAST_KS,
        PRECISION_5_FAST_KS,
        PRECISION_6_FAST_KS,
        PRECISION_7_FAST_KS,
        PRECISION_8_FAST_KS,
        PRECISION_9_FAST_KS,
        PRECISION_10_FAST_KS,
        PRECISION_11_FAST_KS,
    ];

    for params in param_vec {
        let log_precision = params.log_precision;
        let _log_mu = params._log_mu;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let phi_bsk = params.phi_bsk;
        let std_dev_bsk = params.std_dev_bsk;
        let lwe_dimension = params.lwe_dimension;
        let ks1_lwe_modular_std_dev = params.ks1_lwe_modular_std_dev;
        let pbs_level = params.pbs_level;
        let pbs_base_mpg = params.pbs_base_log;
        let ks1_level = params.ks1_level;
        let ks1_base_log = params.ks1_base_log;
        let ks1_polynomial_size = params.ks1_polynomial_size;
        let ks_in_glwe_dimension = params.ks_in_glwe_dimension;
        let phi_in = params.phi_in;
        let ks_out_glwe_dimension = params.ks_out_glwe_dimension;
        let ciphertext_modulus = params.ciphertext_modulus;

        let precision = 1 << (log_precision);
        let delta_log = 63 - log_precision;

        //TODO: to randomize
        let msg = 1;
        let pt = Plaintext(msg << delta_log);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        //Shared and partial key generations
        let glwe_secret_key = allocate_and_generate_new_binary_partial_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            PartialGlweSecretKeyRandomCoefCount(phi_bsk),
            &mut secret_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

        let mut large_glwe_secret_key_without_shared =
            GlweSecretKey::new_empty_key(0u64, ks_in_glwe_dimension, ks1_polynomial_size);

        large_glwe_secret_key_without_shared.as_mut()[0..phi_bsk - lwe_dimension.0]
            .copy_from_slice(&glwe_secret_key.as_ref()[lwe_dimension.0..phi_bsk]);

        let small_glwe_secret_key =
            allocate_and_generate_new_shared_glwe_secret_key_from_glwe_secret_key(
                // large_glwe_secret_key_without_shared.clone(),
                &glwe_secret_key,
                ks_out_glwe_dimension,
                lwe_dimension.0,
                ks1_polynomial_size,
            );

        let mut ggsw = PseudoGgswCiphertext::new(
            0u64,
            ks_in_glwe_dimension.to_glwe_size(),
            ks_out_glwe_dimension.to_glwe_size(),
            ks1_polynomial_size,
            ks1_base_log,
            ks1_level,
            ciphertext_modulus,
        );

        //Encryption
        let mut large_lwe = LweCiphertext::new(
            0u64,
            large_lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        encrypt_lwe_ciphertext(
            &large_lwe_secret_key,
            &mut large_lwe,
            pt,
            std_dev_bsk,
            &mut encryption_generator,
        );

        let mut split_large_lwe =
            LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

        split_large_lwe.as_mut()[0..lwe_dimension.0]
            .iter_mut()
            .zip(large_lwe.as_ref()[0..lwe_dimension.0].iter())
            .for_each(|(dst, &src)| *dst = src);

        let body = split_large_lwe.get_mut_body().data;
        *body = *large_lwe.get_body().data;

        let mut split_large_lwe_to_ks = LweCiphertext::new(
            0u64,
            LweSize(phi_bsk - lwe_dimension.0 + 1),
            ciphertext_modulus,
        );

        split_large_lwe_to_ks.as_mut()[0..phi_bsk - lwe_dimension.0]
            .iter_mut()
            .zip(large_lwe.as_ref()[lwe_dimension.0..phi_bsk].iter())
            .for_each(|(dst, &src)| *dst = src);

        let mut nks_kin_glwe = GlweCiphertext::new(
            0u64,
            ks_in_glwe_dimension.to_glwe_size(),
            ks1_polynomial_size,
            ciphertext_modulus,
        );

        encrypt_pseudo_ggsw_ciphertext(
            &small_glwe_secret_key,
            &large_glwe_secret_key_without_shared,
            &mut ggsw,
            ks1_lwe_modular_std_dev,
            &mut encryption_generator,
        );

        //Memory stuff
        let fft = Fft::new(ks1_polynomial_size);
        let fft = fft.as_view();
        let mut buffers = ComputationBuffers::new();

        let buffer_size_req =
            add_external_product_fast_keyswitch_assign_mem_optimized_requirement::<u64>(
                small_glwe_secret_key.glwe_dimension(),
                ks1_polynomial_size,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required();

        let buffer_size_req = buffer_size_req.max(
            convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );

        buffers.resize(10 * buffer_size_req);

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
            fft,
            buffers.stack(),
        );

        let mut glwe_after_ks = GlweCiphertext::new(
            0u64,
            ks_out_glwe_dimension.to_glwe_size(),
            ks1_polynomial_size,
            ciphertext_modulus,
        );

        let mut small_lwe_secret_key = LweSecretKey::new_empty_key(0u64, lwe_dimension);
        small_lwe_secret_key.as_mut()[0..lwe_dimension.0].copy_from_slice(
            &glwe_secret_key.clone().into_lwe_secret_key().as_ref()[0..lwe_dimension.0],
        );

        let mut bsk = LweBootstrapKey::new(
            0,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_mpg,
            pbs_level,
            lwe_dimension,
            ciphertext_modulus,
        );

        par_generate_lwe_bootstrap_key(
            &small_lwe_secret_key,
            &glwe_secret_key,
            &mut bsk,
            std_dev_bsk,
            &mut encryption_generator,
        );

        let mut fbsk = FourierLweBootstrapKey::new(
            small_lwe_secret_key.lwe_dimension(),
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_mpg,
            pbs_level,
        );

        convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

        drop(bsk);

        let accumulator = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            precision,
            ciphertext_modulus,
            1 << delta_log,
            |x| x,
        );

        let mut out_pbs_ct = LweCiphertext::new(
            0u64,
            large_lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        let bench_id = format!("FAST_KS::{}", params.name());

        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                partial_convert_lwe_ciphertext_into_constant_glwe_ciphertext(
                    &split_large_lwe_to_ks,
                    &mut nks_kin_glwe,
                    phi_in,
                );

                let large_glwe_without_shared = nks_kin_glwe.clone();

                add_external_product_fast_keyswitch_assign_mem_optimized(
                    &mut glwe_after_ks,
                    &fourier_ggsw,
                    &large_glwe_without_shared,
                    fft,
                    buffers.stack(),
                );

                //Encryption
                let mut lwe_after_partial_sample_extract =
                    LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
                partial_extract_lwe_sample_from_glwe_ciphertext(
                    &glwe_after_ks,
                    &mut lwe_after_partial_sample_extract,
                    MonomialDegree(0),
                    lwe_dimension.0,
                );

                //Sum with initial ct
                lwe_after_partial_sample_extract.as_mut()[0..lwe_dimension.0]
                    .iter_mut()
                    .zip(split_large_lwe.as_ref()[0..lwe_dimension.0].iter())
                    .for_each(|(dst, &src)| *dst = dst.wrapping_add(src));

                let body = lwe_after_partial_sample_extract.get_mut_body().data;
                *body = body.wrapping_add(*split_large_lwe.get_body().data);

                programmable_bootstrap_lwe_ciphertext(
                    &lwe_after_partial_sample_extract,
                    &mut out_pbs_ct,
                    &accumulator,
                    &fbsk,
                );
            })
        });
    }
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
