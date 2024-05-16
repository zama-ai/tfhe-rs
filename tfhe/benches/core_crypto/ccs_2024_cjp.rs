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
    CJPParam<u64> =>
    PRECISION_1_CJP,
    PRECISION_2_CJP,
    PRECISION_3_CJP,
    PRECISION_4_CJP,
    PRECISION_5_CJP,
    PRECISION_6_CJP,
    PRECISION_7_CJP,
    PRECISION_8_CJP,
    PRECISION_9_CJP,
    PRECISION_10_CJP,
    PRECISION_11_CJP,
);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CJPParam<Scalar: UnsignedTorus> {
    pub log_precision: usize,
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub std_dev_bsk: StandardDev,
    pub lwe_dimension: LweDimension,
    pub ks1_lwe_modular_std_dev: StandardDev,
    pub pbs_level: DecompositionLevelCount,
    pub pbs_base_log: DecompositionBaseLog,
    pub ks1_level: DecompositionLevelCount,
    pub ks1_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

// CJP
// p,log(nu),  k,  N, stddev,    n, stddev, br_l,br_b, ks_l,ks_b,  cost
// 1,      1,  5,  8, -31.07,  588, -12.66,    1,  15,    3,   3, 31445684
// 2,      2,  6,  8, -37.88,  668, -14.79,    1,  18,    3,   4, 42387300
// 3,      3,  4,  9, -51.49,  720, -16.17,    1,  21,    3,   4, 63333680
// 4,      4,  2, 10, -51.49,  788, -17.98,    1,  23,    3,   4, 78607596
// 5,      5,  1, 11, -51.49,  840, -19.36,    1,  23,    6,   3, 118525112
// 6,      6,  1, 12, -62.00,  840, -19.36,    2,  14,    5,   3, 347139256
// 7,      7,  1, 13, -62.00,  896, -20.85,    2,  15,    6,   3, 797064320
// 8,      8,  1, 14, -62.00,  968, -22.77,    3,  11,    6,   3, 2351201336
// 9,      9,  1, 15, -62.00, 1024, -24.26,    4,   9,    7,   3, 6510246912
// 10,     10,  1, 16, -62.00, 1096, -26.17,    6,   6,   12,   2, 20813446072
// 11,     11,  1, 17, -62.00, 1132, -27.13,   20,   2,   13,   2, 128439942036

pub const PRECISION_1_CJP: CJPParam<u64> = CJPParam {
    log_precision: 1,
    _log_mu: 1,
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    std_dev_bsk: StandardDev(4.43606636507407e-10),
    lwe_dimension: LweDimension(588),
    ks1_lwe_modular_std_dev: StandardDev(0.000154511302974888),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(15),
    ks1_level: DecompositionLevelCount(3),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 2,      2,  6,  8, -37.88,  668, -14.79,    1,  18,    3,   4, 42387300
pub const PRECISION_2_CJP: CJPParam<u64> = CJPParam {
    log_precision: 2,
    _log_mu: 2,
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    std_dev_bsk: StandardDev(3.95351839879752e-12),
    lwe_dimension: LweDimension(668),
    ks1_lwe_modular_std_dev: StandardDev(0.0000352993220185940),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks1_level: DecompositionLevelCount(3),
    ks1_base_log: DecompositionBaseLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 3,      3,  4,  9, -51.49,  720, -16.17,    1,  21,    3,   4, 63333680
pub const PRECISION_3_CJP: CJPParam<u64> = CJPParam {
    log_precision: 3,
    _log_mu: 3,
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    std_dev_bsk: StandardDev(3.16202663074765e-16),
    lwe_dimension: LweDimension(720),
    ks1_lwe_modular_std_dev: StandardDev(0.0000135626629816676),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(21),
    ks1_level: DecompositionLevelCount(3),
    ks1_base_log: DecompositionBaseLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 4,      4,  2, 10, -51.49,  788, -17.98,    1,  23,    3,   4, 78607596
pub const PRECISION_4_CJP: CJPParam<u64> = CJPParam {
    log_precision: 4,
    _log_mu: 4,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    std_dev_bsk: StandardDev(3.16202663074765e-16),
    lwe_dimension: LweDimension(788),
    ks1_lwe_modular_std_dev: StandardDev(3.86794845500957e-6),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(3),
    ks1_base_log: DecompositionBaseLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 5,      5,  1, 11, -51.49,  840, -19.36,    1,  23,    6,   3, 118525112
pub const PRECISION_5_CJP: CJPParam<u64> = CJPParam {
    log_precision: 5,
    _log_mu: 5,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    std_dev_bsk: StandardDev(3.16202663074765e-16),
    lwe_dimension: LweDimension(840),
    ks1_lwe_modular_std_dev: StandardDev(1.48613849575138e-6),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(6),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 6,      6,  1, 12, -62.00,  840, -19.36,    2,  14,    5,   3, 347139256
pub const PRECISION_6_CJP: CJPParam<u64> = CJPParam {
    log_precision: 6,
    _log_mu: 6,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(840),
    ks1_lwe_modular_std_dev: StandardDev(1.48613849575138e-6),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(14),
    ks1_level: DecompositionLevelCount(5),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 7,      7,  1, 13, -62.00,  896, -20.85,    2,  15,    6,   3, 797064320
pub const PRECISION_7_CJP: CJPParam<u64> = CJPParam {
    log_precision: 7,
    _log_mu: 7,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(896),
    ks1_lwe_modular_std_dev: StandardDev(5.29083953889772e-7),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(15),
    ks1_level: DecompositionLevelCount(6),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 8,      8,  1, 14, -62.00,  968, -22.77,    3,  11,    6,   3, 2351201336
pub const PRECISION_8_CJP: CJPParam<u64> = CJPParam {
    log_precision: 8,
    _log_mu: 8,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(968),
    ks1_lwe_modular_std_dev: StandardDev(1.39812821058259e-7),
    pbs_level: DecompositionLevelCount(3),
    pbs_base_log: DecompositionBaseLog(11),
    ks1_level: DecompositionLevelCount(6),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 9,      9,  1, 15, -62.00, 1024, -24.26,    4,   9,    7,   3, 6510246912
pub const PRECISION_9_CJP: CJPParam<u64> = CJPParam {
    log_precision: 9,
    _log_mu: 9,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(1024),
    ks1_lwe_modular_std_dev: StandardDev(4.97751187937479e-8),
    pbs_level: DecompositionLevelCount(4),
    pbs_base_log: DecompositionBaseLog(9),
    ks1_level: DecompositionLevelCount(7),
    ks1_base_log: DecompositionBaseLog(3),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 10,     10,  1, 16, -62.00, 1096, -26.17,    6,   6,   12,   2, 20813446072
pub const PRECISION_10_CJP: CJPParam<u64> = CJPParam {
    log_precision: 10,
    _log_mu: 10,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(1096),
    ks1_lwe_modular_std_dev: StandardDev(1.32447880680348e-8),
    pbs_level: DecompositionLevelCount(6),
    pbs_base_log: DecompositionBaseLog(6),
    ks1_level: DecompositionLevelCount(12),
    ks1_base_log: DecompositionBaseLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// 11,     11,  1, 17, -62.00, 1132, -27.13,   20,   2,   13,   2, 128439942036
pub const PRECISION_11_CJP: CJPParam<u64> = CJPParam {
    log_precision: 11,
    _log_mu: 11,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(1132),
    ks1_lwe_modular_std_dev: StandardDev(6.80857487193794e-9),
    pbs_level: DecompositionLevelCount(20),
    pbs_base_log: DecompositionBaseLog(2),
    ks1_level: DecompositionLevelCount(13),
    ks1_base_log: DecompositionBaseLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
};

fn criterion_bench(c: &mut Criterion) {
    let param_vec = [
        PRECISION_1_CJP,
        PRECISION_2_CJP,
        PRECISION_3_CJP,
        PRECISION_4_CJP,
        PRECISION_5_CJP,
        PRECISION_6_CJP,
        PRECISION_7_CJP,
        PRECISION_8_CJP,
        PRECISION_9_CJP,
        PRECISION_10_CJP,
        PRECISION_11_CJP,
    ];

    for params in param_vec {
        let log_precision = params.log_precision;
        let _log_mu = params._log_mu;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let std_dev_bsk = params.std_dev_bsk;
        let lwe_dimension = params.lwe_dimension;
        let ks1_lwe_modular_std_dev = params.ks1_lwe_modular_std_dev;
        let pbs_level = params.pbs_level;
        let pbs_base_mpg = params.pbs_base_log;
        let ks1_level = params.ks1_level;
        let ks1_base_log = params.ks1_base_log;
        let ciphertext_modulus = params.ciphertext_modulus;

        let precision = 1 << (log_precision);
        // let mu = 1<< _log_mu;
        // let carry = (mu*(precision -1) +1)/precision;
        // let log_carry = ((carry as f32).log2().ceil()) as usize;
        // let delta_log = 63 - (log_precision + log_carry);

        //println!("Delta log = {:?}", delta_log);

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

        let small_lwe_secret_key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
        let large_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let large_lwe_secret_key = large_glwe_secret_key.clone().into_lwe_secret_key();

        //KSK Generation
        let ksk_large_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_secret_key,
            &small_lwe_secret_key,
            ks1_base_log,
            ks1_level,
            ks1_lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
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

        //KS
        let mut small_lwe =
            LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

        //PBS PART
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
            &large_glwe_secret_key,
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
            |x| x & 1,
        );

        let mut out_pbs_ct = LweCiphertext::new(
            0u64,
            large_lwe_secret_key.lwe_dimension().to_lwe_size(),
            ciphertext_modulus,
        );

        let bench_id = format!("CJP::{}", params.name());

        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                keyswitch_lwe_ciphertext(&ksk_large_to_small, &large_lwe, &mut small_lwe);
                programmable_bootstrap_lwe_ciphertext(
                    &small_lwe,
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

// #[test]
// fn test_CJP() {
//     let param_vec = [
//         PRECISION_1_CJP,
//         PRECISION_2_CJP,
//         PRECISION_3_CJP,
//         PRECISION_4_CJP,
//         PRECISION_5_CJP,
//         // PRECISION_6_CJP,
//         // PRECISION_7_CJP,
//         // PRECISION_8_CJP,
//         // PRECISION_9_CJP,
//         // PRECISION_10_CJP,
//         // PRECISION_11_CJP,
//     ];
//     for params in param_vec {
//         to_gen_test_CJP(params);
//     }
// }
