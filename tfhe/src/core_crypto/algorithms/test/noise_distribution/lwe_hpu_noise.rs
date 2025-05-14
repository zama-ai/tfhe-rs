use super::*;
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;
use crate::core_crypto::commons::test_tools::{torus_modular_diff, variance};
use std::io;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_HPU_TESTS: usize = 5;
const NB_PBS: usize = 200;

#[derive(Clone, Copy)]
pub struct HpuTestParams {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus_log: CiphertextModulusLog,
    pub ct_width: usize,
    pub ksk_width: usize,
    pub norm2: u64,
    pub ntt_modulus: u64,
}
#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_HPU_44_KS_21: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(1.259_780_968_897_627_7e-5),
    glwe_modular_std_dev: StandardDev(2.2737367544323206e-13),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 44,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 17592186028033,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(786),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(5.314_123_935_599_821e-6),
    glwe_modular_std_dev: StandardDev(9.1881734381394e-16),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(8),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(804),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(5.963_599_673_924_788e-6),
    glwe_modular_std_dev: StandardDev(2.8452674713391114e-15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(8),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_NATIVE_U64: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(0.000007069849454709433),
    glwe_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 64,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(841),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(3.149_667_468_577_243_5e-6),
    glwe_modular_std_dev: StandardDev(2.845267479601915e-15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 64,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

pub fn get_modulo_value<T: UnsignedInteger>(modulus: &CiphertextModulus<T>) -> u128 {
    if modulus.is_native_modulus() {
        let converted: CiphertextModulus<u128> = modulus.try_to().unwrap();
        u128::cast_from(converted.get_custom_modulus())
    } else {
        u128::cast_from(modulus.get_custom_modulus())
    }
}

//fn lwe_noise_distribution_hpu<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64>>(
fn hpu_noise_distribution(params: HpuTestParams) {
    let lwe_dimension = params.lwe_dimension;
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let glwe_modular_std_dev = params.glwe_modular_std_dev;
    let ciphertext_modulus = CiphertextModulus::try_new_power_of_2(params.ct_width).unwrap();
    let message_modulus_log = params.message_modulus_log;
    let ks_decomp_base_log = params.ks_base_log;
    let ks_decomp_level_count = params.ks_level;
    let pbs_decomp_base_log = params.pbs_base_log;
    let pbs_decomp_level_count = params.pbs_level;
    let ksk_modulus = CiphertextModulus::try_new_power_of_2(params.ksk_width).unwrap();
    let ntt_modulus = CiphertextModulus::<u64>::new(params.ntt_modulus as u128);

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let ksk_encoding_with_padding = get_encoding_with_padding(ksk_modulus);
    let expected_variance = lwe_modular_std_dev.get_variance();

    let mut rsc = TestResources::new();

    let msg_modulus = 1 << message_modulus_log.0;
    let mut msg: u64 = msg_modulus;
    let delta: u64 = encoding_with_padding / msg_modulus;
    let ks_delta: u64 = ksk_encoding_with_padding / msg_modulus;
    let norm2 = params.norm2;

    let num_samples = NB_PBS * NB_HPU_TESTS * (msg as usize);
    let mut noise_samples = (0..4)
        .map(|_| Vec::with_capacity(num_samples))
        .collect::<Vec<_>>();
    let min_lwe_variance =
        variance_formula::secure_noise::minimal_lwe_variance_for_128_bits_security_gaussian(
            lwe_dimension,
            get_modulo_value(&ciphertext_modulus) as f64,
        );
    let min_glwe_variance =
        variance_formula::secure_noise::minimal_glwe_variance_for_128_bits_security_gaussian(
            glwe_dimension,
            polynomial_size,
            get_modulo_value(&ciphertext_modulus) as f64,
        );
    println!("ciphertext_modulus {ciphertext_modulus:?} ksk_modulus {ksk_modulus:?} message_modulus_log {message_modulus_log:?} encoding_with_padding {encoding_with_padding } expected_variance {expected_variance:?} msg_modulus {msg_modulus} msg {msg} delta {delta}");
    println!(
        "min lwe var {:?} ({:?}) - param: {:?}",
        min_lwe_variance.0,
        min_lwe_variance.get_standard_dev(),
        lwe_modular_std_dev
    );
    println!(
        "min glwe var {:?} ({:?}) - param: {:?}",
        min_glwe_variance.0,
        min_glwe_variance.get_standard_dev(),
        glwe_modular_std_dev
    );

    let f = |x: u64| x.wrapping_rem(msg_modulus);

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

    let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );
    let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut rsc.secret_random_generator,
    );
    let blwe_sk = glwe_sk.clone().into_lwe_secret_key();
    let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
        &blwe_sk,
        &lwe_sk,
        ks_decomp_base_log,
        ks_decomp_level_count,
        DynamicDistribution::new_gaussian_from_std_dev(lwe_modular_std_dev),
        ksk_modulus,
        &mut rsc.encryption_random_generator,
    );
    println!(
        "n {:?} k {:?} N {:?} k*N {:?}",
        lwe_sk.lwe_dimension(),
        glwe_dimension,
        polynomial_size,
        blwe_sk.lwe_dimension()
    );

    // it includes variance of mod switch from KS modulus to 2N
    let (exp_add_ks_variance, _exp_modswitch_variance) =
        variance_formula::lwe_keyswitch::keyswitch_additive_variance_128_bits_security_gaussian(
            glwe_dimension,
            polynomial_size,
            lwe_sk.lwe_dimension(),
            ks_decomp_level_count,
            ks_decomp_base_log,
            get_modulo_value(&ksk_modulus) as f64,
            get_modulo_value(&ciphertext_modulus) as f64,
        );
    println!(
        "KS additive theo variance: {:?} theo std_dev {:?} / {:?}",
        exp_add_ks_variance.0,
        exp_add_ks_variance.get_standard_dev(),
        exp_add_ks_variance.get_log_standard_dev()
    );
    let mut bsk = LweBootstrapKey::new(
        0,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_decomp_base_log,
        pbs_decomp_level_count,
        lwe_dimension,
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &lwe_sk,
        &glwe_sk,
        &mut bsk,
        DynamicDistribution::new_gaussian_from_std_dev(glwe_modular_std_dev),
        &mut rsc.encryption_random_generator,
    );

    let exp_pbs_variance =
        variance_formula::lwe_programmable_bootstrap::pbs_variance_128_bits_security_gaussian(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            pbs_decomp_level_count,
            pbs_decomp_base_log,
            get_modulo_value(&ciphertext_modulus) as f64,
            get_modulo_value(&ntt_modulus) as f64,
        );
    println!(
        "PBS theo variance without modswitch: {:?} std_dev {:?}/{:?}",
        exp_pbs_variance.0,
        exp_pbs_variance.get_standard_dev(),
        exp_pbs_variance.get_log_standard_dev()
    );

    let mut nbsk = NttLweBootstrapKeyOwned::<u64>::new(
        0,
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
        ntt_modulus,
    );

    let mut buffers = ComputationBuffers::new();

    let ntt = Ntt64::new(ntt_modulus, nbsk.polynomial_size());
    let ntt = ntt.as_view();

    let stack_size = programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized_requirement(
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ntt,
    )
    .unwrap()
    .try_unaligned_bytes_required()
    .unwrap();

    buffers.resize(stack_size);

    par_convert_standard_lwe_bootstrap_key_to_ntt64(&bsk, &mut nbsk, NttLweBootstrapKeyOption::Raw);

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        ciphertext_modulus
    ));

    while msg != 0 {
        msg = msg.wrapping_sub(1);
        for i in 0..NB_HPU_TESTS {
            let mut ct =
                LweCiphertext::new(0, blwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            let mut out_ks_ct =
                LweCiphertext::new(0, ksk_big_to_small.output_lwe_size(), ksk_modulus);

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &blwe_sk,
                &mut ct,
                plaintext,
                DynamicDistribution::new_gaussian_from_std_dev(lwe_modular_std_dev),
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&blwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_diff = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples[0].push(torus_diff);

            // re-generate BSK
            par_generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut bsk,
                DynamicDistribution::new_gaussian_from_std_dev(glwe_modular_std_dev),
                &mut rsc.encryption_random_generator,
            );
            nbsk = NttLweBootstrapKeyOwned::<u64>::new(
                0,
                bsk.input_lwe_dimension(),
                bsk.glwe_size(),
                bsk.polynomial_size(),
                bsk.decomposition_base_log(),
                bsk.decomposition_level_count(),
                ntt_modulus,
            );
            par_convert_standard_lwe_bootstrap_key_to_ntt64(
                &bsk,
                &mut nbsk,
                NttLweBootstrapKeyOption::Raw,
            );
            assert!(check_encrypted_content_respects_mod(
                &*bsk,
                ciphertext_modulus
            ));

            for j in 0..NB_PBS {
                // b = b - (Delta * msg) to have an encryption of 0
                lwe_ciphertext_plaintext_sub_assign(&mut ct, plaintext);

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus
                ));
                // * norm2
                //lwe_ciphertext_cleartext_mul_assign(&mut ct,
                // Cleartext(Scalar::cast_from(norm2)));
                lwe_ciphertext_cleartext_mul_assign(&mut ct, Cleartext(norm2));

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus
                ));

                let decrypted_prodnorm2 = decrypt_lwe_ciphertext(&blwe_sk, &ct);

                let decode_prodnorm2 = round_decode(decrypted_prodnorm2.0, delta) % msg_modulus;

                let torus_diff = torus_modular_diff(0, decrypted_prodnorm2.0, ciphertext_modulus);
                assert_eq!(0, decode_prodnorm2);
                noise_samples[1].push(torus_diff);
                // b = b + (Delta * msg) to have a noisy encryption of msg
                lwe_ciphertext_plaintext_add_assign(&mut ct, plaintext);

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus
                ));

                // Compute key-switch
                keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut out_ks_ct);

                assert!(check_encrypted_content_respects_mod(
                    &out_ks_ct,
                    ksk_modulus
                ));
                // Noise extraction and decryption check
                // NB: After key-switch ciphertext is on ksk_modulus != ct_modulus

                let decrypted_after_ks = decrypt_lwe_ciphertext(&lwe_sk, &out_ks_ct);

                let decode_after_ks = round_decode(decrypted_after_ks.0, ks_delta) % msg_modulus;

                assert_eq!(msg, decode_after_ks);

                // do modulo switch on plaintext post KS only if necessary
                let cm_f = get_modulo_value(&ciphertext_modulus);
                let ksm_f = get_modulo_value(&ksk_modulus);
                let torus_diff = if cm_f == ksm_f {
                    torus_modular_diff(plaintext.0, decrypted_after_ks.0, ciphertext_modulus)
                } else {
                    let decrypted_after_ks_modswitched =
                        decrypted_after_ks.0 * ((cm_f / ksm_f) as u64);
                    torus_modular_diff(
                        plaintext.0,
                        decrypted_after_ks_modswitched,
                        ciphertext_modulus,
                    )
                };

                noise_samples[2].push(torus_diff);

                // Compute PBS with NTT
                programmable_bootstrap_ntt64_bnf_lwe_ciphertext_mem_optimized(
                    &out_ks_ct,
                    &mut ct,
                    &accumulator,
                    &nbsk,
                    ntt,
                    buffers.stack(),
                );

                assert!(check_encrypted_content_respects_mod(
                    &ct,
                    ciphertext_modulus
                ));

                let decrypted_pbs = decrypt_lwe_ciphertext(&blwe_sk, &ct);

                let decoded_pbs = round_decode(decrypted_pbs.0, delta) % msg_modulus;

                assert_eq!(decoded_pbs, f(msg));
                let torus_diff =
                    torus_modular_diff(plaintext.0, decrypted_pbs.0, ciphertext_modulus);
                println!("after pbs (msg={msg},test_nb={i}/{NB_HPU_TESTS},pbs_nb={j}/{NB_PBS}): plaintext {:?} post pbs {:?} torus_diff {:?}", plaintext.0, decrypted_pbs.0, torus_diff);
                noise_samples[3].push(torus_diff);
            }
        }
    }

    let encryption_variance = variance(&noise_samples[0]);
    let bynorm2_variance = variance(&noise_samples[1]);
    let after_ks_variance = variance(&noise_samples[2]);
    let after_pbs_variance = variance(&noise_samples[3]);
    println!(
        "exp var {:?} encrypt var {:?} bynorm2 var {} after_ks_variance {} after_pbs_variance {:?}",
        expected_variance.0,
        encryption_variance.0,
        bynorm2_variance.0,
        after_ks_variance.0,
        after_pbs_variance.0
    );
    // variance after *norm2 must be around (exp_pbs_variance)*(norm2**2)
    // variance after KS must be around (exp_pbs_variance)*(norm2**2)+exp_add_ks_variance
    // variance after PBS must be around (exp_pbs_variance)
    let expected_bynorm2_variance = Variance(exp_pbs_variance.0 * (norm2 as f64).powf(2.0));
    let expected_after_ks_variance = Variance(expected_bynorm2_variance.0 + exp_add_ks_variance.0);

    let mut wtr = csv::Writer::from_writer(io::stdout());
    let _ = wtr.write_record([
        "data type",
        "encrypt exp",
        "encrypt",
        "post *norm2",
        "post KS",
        "theo KS",
        "post PBS",
        "theo PBS",
    ]);
    let _ = wtr.write_record([
        "variances",
        expected_variance.0.to_string().as_str(),
        encryption_variance.0.to_string().as_str(),
        bynorm2_variance.0.to_string().as_str(),
        after_ks_variance.0.to_string().as_str(),
        expected_after_ks_variance.0.to_string().as_str(),
        after_pbs_variance.0.to_string().as_str(),
        exp_pbs_variance.0.to_string().as_str(),
    ]);
    let _ = wtr.write_record([
        "std_dev",
        expected_variance.get_standard_dev().0.to_string().as_str(),
        encryption_variance
            .get_standard_dev()
            .0
            .to_string()
            .as_str(),
        bynorm2_variance.get_standard_dev().0.to_string().as_str(),
        after_ks_variance.get_standard_dev().0.to_string().as_str(),
        expected_after_ks_variance
            .get_standard_dev()
            .0
            .to_string()
            .as_str(),
        after_pbs_variance.get_standard_dev().0.to_string().as_str(),
        exp_pbs_variance.get_standard_dev().0.to_string().as_str(),
    ]);
    let _ = wtr.write_record([
        "log2 std_dev + ct_w",
        (expected_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (encryption_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (bynorm2_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (after_ks_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (expected_after_ks_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (after_pbs_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (exp_pbs_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
    ]);

    let var_pbs_abs_diff = (exp_pbs_variance.0 - after_pbs_variance.0).abs();
    let pbs_tolerance_thres = RELATIVE_TOLERANCE * exp_pbs_variance.0;

    let var_ksk_abs_diff = (expected_after_ks_variance.0 - after_ks_variance.0).abs();
    let ks_tolerance_thres = RELATIVE_TOLERANCE * expected_after_ks_variance.0;

    let var_bynorm2_abs_diff = (expected_bynorm2_variance.0 - bynorm2_variance.0).abs();
    let bynorm2_tolerance_thres = RELATIVE_TOLERANCE * expected_bynorm2_variance.0;

    let after_pbs_errbit = params.ct_width as f64 + after_pbs_variance.get_log_standard_dev().0;
    let after_pbs_exp_errbit = params.ct_width as f64 + exp_pbs_variance.get_log_standard_dev().0;
    let bynorm2_errbit = params.ct_width as f64 + bynorm2_variance.get_log_standard_dev().0;
    let bynorm2_exp_errbit =
        params.ct_width as f64 + expected_bynorm2_variance.get_log_standard_dev().0;
    let after_ks_errbit = params.ct_width as f64 + after_ks_variance.get_log_standard_dev().0;
    let after_ks_exp_errbit =
        params.ct_width as f64 + expected_after_ks_variance.get_log_standard_dev().0;
    assert!(
        var_pbs_abs_diff < pbs_tolerance_thres,
        "Absolute difference for after PBS is incorrect: {var_pbs_abs_diff} >= {pbs_tolerance_thres}, \
        got variance: {after_pbs_variance:?} - log2(str_dev): {after_pbs_errbit:?}, \
        expected variance: {exp_pbs_variance:?} - log2(std_dev): {after_pbs_exp_errbit:?}"
    );
    assert!(
        var_bynorm2_abs_diff < bynorm2_tolerance_thres,
        "Absolute difference for after *norm2 in incorrect: {var_bynorm2_abs_diff} >= {bynorm2_tolerance_thres} \
        got variance: {bynorm2_variance:?} - log2(str_dev): {bynorm2_errbit:?}, \
        expected variance: {expected_bynorm2_variance:?} - log2(std_dev): {bynorm2_exp_errbit:?}"
    );
    assert!(
        (var_ksk_abs_diff < ks_tolerance_thres) || (after_ks_errbit < after_ks_exp_errbit && (after_ks_exp_errbit - after_ks_errbit < 1f64)),
        "Absolute difference for after KS is incorrect: {var_ksk_abs_diff} >= {ks_tolerance_thres} or more than 1 bit away \
        got variance: {after_ks_variance:?} - log2(str_dev): {after_ks_errbit:?}, \
        expected variance: {expected_after_ks_variance:?} - log2(std_dev): {after_ks_exp_errbit:?}"
    );
}

create_parameterized_test!(hpu_noise_distribution {
    //HPU_TEST_PARAMS_4_BITS_NATIVE_U64,
    //HPU_TEST_PARAMS_4_BITS_HPU_44_KS_21,
    //HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21,
    HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132,
    HPU_TEST_PARAMS_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN,
});
