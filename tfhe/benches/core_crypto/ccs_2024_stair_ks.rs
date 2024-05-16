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
    StairKSParam<u64> =>
    PRECISION_1_STAIR,
    PRECISION_2_STAIR,
    PRECISION_3_STAIR,
    PRECISION_4_STAIR,
    PRECISION_5_STAIR,
    PRECISION_6_STAIR,
    PRECISION_7_STAIR,
    PRECISION_8_STAIR,
    PRECISION_9_STAIR,
    PRECISION_10_STAIR,
    PRECISION_11_STAIR,
);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct StairKSParam<Scalar: UnsignedTorus> {
    pub log_precision: usize,
    pub _log_mu: usize,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub phi: usize,
    pub std_dev_bsk: StandardDev,
    pub lwe_dimension: LweDimension,
    pub ks1_lwe_modular_std_dev: StandardDev,
    pub ks2_lwe_modular_std_dev: StandardDev,
    pub pbs_level: DecompositionLevelCount,
    pub pbs_base_log: DecompositionBaseLog,
    pub ks1_level: DecompositionLevelCount,
    pub ks1_base_log: DecompositionBaseLog,
    pub ks2_level: DecompositionLevelCount,
    pub ks2_base_log: DecompositionBaseLog,
    pub size1: usize,
    pub size2: usize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}
// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 1,   1,  5,  8, 1280, -31.07,   532, -17.82, -11.17,    1,  15,    1,   9,    4,
// 2,  498,  250, 26700580
pub const PRECISION_1_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 1,
    _log_mu: 1,
    glwe_dimension: GlweDimension(5),
    polynomial_size: PolynomialSize(256),
    phi: 1280,
    std_dev_bsk: StandardDev(4.43606636507407e-10),
    lwe_dimension: LweDimension(532),
    ks1_lwe_modular_std_dev: StandardDev(4.32160905950851e-6),
    ks2_lwe_modular_std_dev: StandardDev(0.000434005215413364),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(15),
    ks1_level: DecompositionLevelCount(1),
    ks1_base_log: DecompositionBaseLog(9),
    ks2_level: DecompositionLevelCount(4),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 498,
    size2: 250,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 2,   2,  6,  8, 1536, -37.88,   576, -20.85, -12.34,    1,  18,    1,  10,    5,
// 2,  640,  320, 35091584
pub const PRECISION_2_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 2,
    _log_mu: 2,
    glwe_dimension: GlweDimension(6),
    polynomial_size: PolynomialSize(256),
    phi: 1536,
    std_dev_bsk: StandardDev(3.953518398797519e-12),
    lwe_dimension: LweDimension(576),
    ks1_lwe_modular_std_dev: StandardDev(5.290839538897724e-07),
    ks2_lwe_modular_std_dev: StandardDev(0.00019288117965414483),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks1_level: DecompositionLevelCount(1),
    ks1_base_log: DecompositionBaseLog(10),
    ks2_level: DecompositionLevelCount(5),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 640,
    size2: 320,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 3,   3,  3,  9, 1536, -37.88,   648, -22.13, -14.25,    1,  18,    2,   7,    6,
// 2,  592,  296, 42686328
pub const PRECISION_3_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 3,
    _log_mu: 3,
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    phi: 1536,
    std_dev_bsk: StandardDev(3.95351839879752e-12),
    lwe_dimension: LweDimension(648),
    ks1_lwe_modular_std_dev: StandardDev(2.17874395902014e-7),
    ks2_lwe_modular_std_dev: StandardDev(5.132424409507535e-05),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(18),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(7),
    ks2_level: DecompositionLevelCount(6),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 592,
    size2: 296,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 4,   4,  2, 10, 2048, -51.49,   664, -26.97, -14.68,    1,  22,    1,  13,    6,
// 2,  922,  462, 65150660
pub const PRECISION_4_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 4,
    _log_mu: 4,
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    phi: 2048,
    std_dev_bsk: StandardDev(3.16202663074765e-16),
    lwe_dimension: LweDimension(664),
    ks1_lwe_modular_std_dev: StandardDev(7.60713313301797e-9),
    ks2_lwe_modular_std_dev: StandardDev(0.0000380960250519291),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(22),
    ks1_level: DecompositionLevelCount(1),
    ks1_base_log: DecompositionBaseLog(13),
    ks2_level: DecompositionLevelCount(6),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 922,
    size2: 462,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 5,   5,  1, 11, 2048, -51.49,   732, -28.17, -16.49,    1,  23,    2,   9,    7,
// 2,  877,  439, 94962998
pub const PRECISION_5_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 5,
    _log_mu: 5,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    phi: 2048,
    std_dev_bsk: StandardDev(3.16202663074765e-16),
    lwe_dimension: LweDimension(732),
    ks1_lwe_modular_std_dev: StandardDev(3.31119701700870e-9),
    ks2_lwe_modular_std_dev: StandardDev(0.0000108646407745138),
    pbs_level: DecompositionLevelCount(1),
    pbs_base_log: DecompositionBaseLog(23),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(9),
    ks2_level: DecompositionLevelCount(7),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 877,
    size2: 439,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 6,   6,  1, 12, 2443, -62.00,   748, -31.94, -16.91,    2,  14,    1,  16,    8,
// 2, 1130,  565, 283238205
pub const PRECISION_6_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 6,
    _log_mu: 6,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(748),
    ks1_lwe_modular_std_dev: StandardDev(2.42717974083759e-10),
    ks2_lwe_modular_std_dev: StandardDev(8.12050004923523e-6),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(14),
    ks1_level: DecompositionLevelCount(1),
    ks1_base_log: DecompositionBaseLog(16),
    ks2_level: DecompositionLevelCount(8),
    ks2_base_log: DecompositionBaseLog(2),
    size1: 1130,
    size2: 565,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 7,   7,  1, 13, 2443, -62.00,   776, -32.45, -17.66,    2,  15,    2,  10,   16,
// 1, 1111,  556, 614607038
pub const PRECISION_7_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 7,
    _log_mu: 7,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(776),
    ks1_lwe_modular_std_dev: StandardDev(1.70442007475721e-10),
    ks2_lwe_modular_std_dev: StandardDev(4.82847821796524e-6),
    pbs_level: DecompositionLevelCount(2),
    pbs_base_log: DecompositionBaseLog(15),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(10),
    ks2_level: DecompositionLevelCount(16),
    ks2_base_log: DecompositionBaseLog(1),
    size1: 1111,
    size2: 556,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 8,   8,  1, 14, 2443, -62.00,   816, -33.17, -18.72,    3,  11,    2,   9,   17,
// 1, 1084,  543, 1795749574
pub const PRECISION_8_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 8,
    _log_mu: 8,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(816),
    ks1_lwe_modular_std_dev: StandardDev(1.03474906781522e-10),
    ks2_lwe_modular_std_dev: StandardDev(2.31589295271883e-6),
    pbs_level: DecompositionLevelCount(3),
    pbs_base_log: DecompositionBaseLog(11),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(9),
    ks2_level: DecompositionLevelCount(17),
    ks2_base_log: DecompositionBaseLog(1),
    size1: 1084,
    size2: 543,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 9,   9,  1, 15, 2443, -62.00,   860, -33.94, -19.89,    4,   8,    2,  10,   18,
// 1, 1055,  528, 4992007842
pub const PRECISION_9_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 9,
    _log_mu: 9,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(860),
    ks1_lwe_modular_std_dev: StandardDev(6.06794935209399e-11),
    ks2_lwe_modular_std_dev: StandardDev(1.02923225069468e-6),
    pbs_level: DecompositionLevelCount(4),
    pbs_base_log: DecompositionBaseLog(8),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(10),
    ks2_level: DecompositionLevelCount(18),
    ks2_base_log: DecompositionBaseLog(1),
    size1: 1055,
    size2: 528,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 10,  10,  1, 16, 2443, -62.00,   904, -34.71, -21.06,    6,   6,    2,  11,   19,
// 1, 1026,  513, 15555548076
pub const PRECISION_10_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 10,
    _log_mu: 10,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(904),
    ks1_lwe_modular_std_dev: StandardDev(3.55835153515238e-11),
    ks2_lwe_modular_std_dev: StandardDev(4.77994271508188e-14),
    pbs_level: DecompositionLevelCount(6),
    pbs_base_log: DecompositionBaseLog(6),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(11),
    ks2_level: DecompositionLevelCount(19),
    ks2_base_log: DecompositionBaseLog(1),
    size1: 1026,
    size2: 513,
    ciphertext_modulus: CiphertextModulus::new_native(),
};

// p,log(nu),  k,  N,   phi, stddev,    n, stddev, stddev,  br_l,br_b, ksl1,ksb1, ksl2,ksb2, size1,
// size2,  cost 11,  11,  1, 17, 2443, -62.00,   984, -36.15, -23.19,   12,   3,    2,  11,   21,
// 1,  972,  487, 66586908138
pub const PRECISION_11_STAIR: StairKSParam<u64> = StairKSParam {
    log_precision: 11,
    _log_mu: 11,
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(131072),
    phi: 2443,
    std_dev_bsk: StandardDev(2.16840434497101e-19),
    lwe_dimension: LweDimension(984),
    ks1_lwe_modular_std_dev: StandardDev(1.31149203314392e-11),
    ks2_lwe_modular_std_dev: StandardDev(1.04499545254235e-7),
    pbs_level: DecompositionLevelCount(12),
    pbs_base_log: DecompositionBaseLog(3),
    ks1_level: DecompositionLevelCount(2),
    ks1_base_log: DecompositionBaseLog(11),
    ks2_level: DecompositionLevelCount(21),
    ks2_base_log: DecompositionBaseLog(1),
    size1: 972,
    size2: 487,
    ciphertext_modulus: CiphertextModulus::new_native(),
};
fn criterion_bench(c: &mut Criterion) {
    let param_vec = [
        PRECISION_1_STAIR,
        PRECISION_2_STAIR,
        PRECISION_3_STAIR,
        PRECISION_4_STAIR,
        PRECISION_5_STAIR,
        PRECISION_6_STAIR,
        PRECISION_7_STAIR,
        PRECISION_8_STAIR,
        PRECISION_9_STAIR,
        PRECISION_10_STAIR,
        PRECISION_11_STAIR,
    ];

    for params in param_vec {
        let log_precision = params.log_precision;
        let _log_mu = params._log_mu;
        let glwe_dimension = params.glwe_dimension;
        let polynomial_size = params.polynomial_size;
        let std_dev_bsk = params.std_dev_bsk;
        let lwe_dimension = params.lwe_dimension;
        let ks1_lwe_modular_std_dev = params.ks1_lwe_modular_std_dev;
        let ks2_lwe_modular_std_dev = params.ks2_lwe_modular_std_dev;
        let pbs_level = params.pbs_level;
        let pbs_base_mpg = params.pbs_base_log;
        let ks1_level = params.ks1_level;
        let ks1_base_log = params.ks1_base_log;
        let ks2_level = params.ks2_level;
        let ks2_base_log = params.ks2_base_log;
        let size1 = params.size1;
        let size2 = params.size2;
        let ciphertext_modulus = params.ciphertext_modulus;

        let precision = 1 << (log_precision);
        // let mu = 1<< _log_mu;
        // let carry = (mu*(precision -1) +1)/precision;
        // let log_carry = ((carry as f32).log2().ceil()) as usize;
        // let delta_log = 63 - (log_precision + log_carry);

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
        let large_lwe_dimension_phi = LweDimension(lwe_dimension.0 + size1 + size2);
        let large_lwe_dimension = LweDimension(glwe_dimension.0 * polynomial_size.0);

        let glwe_secret_key = allocate_and_generate_new_binary_partial_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            PartialGlweSecretKeyRandomCoefCount(large_lwe_dimension_phi.0),
            &mut secret_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

        // let large_lwe_secret_key = allocate_and_generate_new_binary_lwe_partial_secret_key
        //     (large_lwe_dimension, &mut secret_generator, large_lwe_dimension_phi);
        // large_lwe_dimension_phi - size1 == lwe_dimension.0 + size2
        let inter_phi = lwe_dimension.0 + size2;
        let inter_lwe_secret_key =
            allocate_and_generate_new_shared_lwe_secret_key_from_lwe_secret_key(
                &large_lwe_secret_key,
                SharedLweSecretKeyCommonCoefCount(inter_phi),
            );

        let small_lwe_secret_key =
            allocate_and_generate_new_shared_lwe_secret_key_from_lwe_secret_key(
                &inter_lwe_secret_key,
                SharedLweSecretKeyCommonCoefCount(lwe_dimension.0),
            );

        // println!("Large Key Dimension = {:?}",large_lwe_secret_key.lwe_dimension().0);
        // println!("Inter Key Dimension = {:?}",inter_lwe_secret_key.lwe_dimension().0);
        // println!("Small Key Dimension = {:?}",small_lwe_secret_key.lwe_dimension().0);
        //
        //
        //
        // println!("Large phi = {:?}",large_lwe_dimension_phi);
        // println!("Inter phi = {:?}",inter_phi);

        //Shrinking KSK generations
        let ksk_large_to_inter = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
            &large_lwe_secret_key,
            &inter_lwe_secret_key,
            SharedLweSecretKeyCommonCoefCount(inter_phi),
            ks1_base_log,
            ks1_level,
            ks1_lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let ksk_inter_to_small = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
            &inter_lwe_secret_key,
            &small_lwe_secret_key,
            SharedLweSecretKeyCommonCoefCount(lwe_dimension.0),
            ks2_base_log,
            ks2_level,
            ks2_lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        //Encryption
        let mut large_lwe =
            LweCiphertext::new(0u64, large_lwe_dimension.to_lwe_size(), ciphertext_modulus);

        encrypt_lwe_ciphertext(
            &large_lwe_secret_key,
            &mut large_lwe,
            pt,
            std_dev_bsk,
            &mut encryption_generator,
        );

        //Shrinking KS
        let mut inter_lwe =
            LweCiphertext::new(0, LweDimension(inter_phi).to_lwe_size(), ciphertext_modulus);

        let mut small_lwe = LweCiphertext::new(0, lwe_dimension.to_lwe_size(), ciphertext_modulus);

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

        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(log_precision + 1),
            DecompositionLevelCount(1),
        );

        shrinking_keyswitch_lwe_ciphertext(&ksk_large_to_inter, &large_lwe, &mut inter_lwe);

        let dec_inter = decrypt_lwe_ciphertext(&inter_lwe_secret_key, &inter_lwe);
        let decoded = decomposer.closest_representable(dec_inter.0) >> delta_log;
        assert_eq!(decoded, msg, "Err after first shrinking KS");

        shrinking_keyswitch_lwe_ciphertext(&ksk_inter_to_small, &inter_lwe, &mut small_lwe);

        let dec_small = decrypt_lwe_ciphertext(&small_lwe_secret_key, &small_lwe);
        let decoded = decomposer.closest_representable(dec_small.0) >> delta_log;
        assert_eq!(decoded, msg, "Err after second shrinking KS");

        programmable_bootstrap_lwe_ciphertext(&small_lwe, &mut out_pbs_ct, &accumulator, &fbsk);

        let dec_large = decrypt_lwe_ciphertext(&large_lwe_secret_key, &out_pbs_ct);
        let decoded = decomposer.closest_representable(dec_large.0) >> delta_log;
        assert_eq!(decoded, msg, "Err after PBS");

        let bench_id = format!("stairKS::{}", params.name());

        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                shrinking_keyswitch_lwe_ciphertext(&ksk_large_to_inter, &large_lwe, &mut inter_lwe);

                shrinking_keyswitch_lwe_ciphertext(&ksk_inter_to_small, &inter_lwe, &mut small_lwe);

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
