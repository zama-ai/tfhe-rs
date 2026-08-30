use super::*;
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;
use crate::core_crypto::commons::test_tools::{
    arithmetic_mean, normality_test_f64, torus_modular_diff, variance,
};
use std::io;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

#[derive(Clone, Copy)]
pub struct HpuTestParams {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
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
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.259_780_968_897_627_7e-5,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2737367544323206e-13,
    )),
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
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.314_123_935_599_821e-6,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.1881734381394e-16,
    )),
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
pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_GAUSSIAN: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(804),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.963_599_673_924_788e-6,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.8452674713391114e-15,
    )),
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
pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(839),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM_2M128: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(8),
    ks_base_log: DecompositionBaseLog(2),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 21,
    //norm2: 8,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

#[allow(unused)]
pub const HPU_TEST_PARAMS_4_BITS_NATIVE_U64: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000007069849454709433,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000000000000029403601535432533,
    )),
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
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.149_667_468_577_243_5e-6,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
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

#[derive(Clone, Copy, PartialEq)]
enum HpuNoiseMode {
    Variance,
    Normality,
}

//fn lwe_noise_distribution_hpu<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64>>(
fn hpu_noise_distribution(
    params: HpuTestParams,
    max_msg_val: u64,
    nb_tests: usize,
    nb_pbs_per_test: usize,
    test_mode: HpuNoiseMode,
) {
    let lwe_dimension = params.lwe_dimension;
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let glwe_noise_distribution = params.glwe_noise_distribution;
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
    let expected_variance = match glwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => {
            glwe_noise_distribution.gaussian_std_dev().get_variance()
        }
        DynamicDistribution::TUniform(tuniform) => Variance(
            ((2.0 * (tuniform.bound_log2() as f64) + 1.0).exp2() + 1.0) / 6.0
                * (-2.0 * (params.ct_width as f64)).exp2(),
        ),
    };

    let mut rsc = TestResources::new();

    let msg_modulus = 1 << message_modulus_log.0;
    assert!(max_msg_val <= msg_modulus, "Cannot start with msg val {max_msg_val:?} with a message_modulus_log of {message_modulus_log:?}");
    let mut msg: u64 = max_msg_val;
    let delta: u64 = encoding_with_padding / msg_modulus;
    let ks_delta: u64 = ksk_encoding_with_padding / msg_modulus;
    let norm2 = params.norm2;

    let num_samples = nb_pbs_per_test * nb_tests * (msg as usize);
    let mut noise_samples = (0..4)
        .map(|_| Vec::with_capacity(num_samples))
        .collect::<Vec<_>>();
    let mut normality_test_samples: Vec<f64> = Vec::with_capacity(nb_pbs_per_test);
    let mut normality_check_result: Vec<f64> = Vec::with_capacity(nb_pbs_per_test);
    let mut expvalue_score_result: Vec<f64> = Vec::with_capacity(nb_pbs_per_test);
    println!("ciphertext_modulus {ciphertext_modulus:?} ksk_modulus {ksk_modulus:?} message_modulus_log {message_modulus_log:?} encoding_with_padding {encoding_with_padding } expected_variance {expected_variance:?} msg_modulus {msg_modulus} msg {msg} delta {delta}");

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

    let lwe_sk =
        test_allocate_and_generate_binary_lwe_secret_key_with_half_hamming_weight(lwe_dimension);

    let glwe_sk = test_allocate_and_generate_binary_glwe_secret_key_with_half_hamming_weight(
        glwe_dimension,
        polynomial_size,
    );

    let blwe_sk = glwe_sk.as_lwe_secret_key();
    let mut ksk_in_kskmod = LweKeyswitchKeyOwned::new(
        0,
        ks_decomp_base_log,
        ks_decomp_level_count,
        blwe_sk.lwe_dimension(),
        lwe_sk.lwe_dimension(),
        ksk_modulus,
    );

    println!(
        "n {:?} k {:?} N {:?} k*N {:?}",
        lwe_sk.lwe_dimension(),
        glwe_dimension,
        polynomial_size,
        blwe_sk.lwe_dimension()
    );

    // it includes variance of mod switch from KS modulus to 2N
    let (exp_add_ks_variance, _exp_modswitch_variance) = match lwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => {
            variance_formula::lwe_keyswitch::keyswitch_additive_variance_132_bits_security_gaussian(
                glwe_dimension,
                polynomial_size,
                lwe_sk.lwe_dimension(),
                ks_decomp_level_count,
                ks_decomp_base_log,
                get_modulo_value(&ksk_modulus) as f64,
                get_modulo_value(&ciphertext_modulus) as f64,
            )
        }
        DynamicDistribution::TUniform(_) => {
            variance_formula::lwe_keyswitch::keyswitch_additive_variance_132_bits_security_tuniform(
                glwe_dimension,
                polynomial_size,
                lwe_sk.lwe_dimension(),
                ks_decomp_level_count,
                ks_decomp_base_log,
                get_modulo_value(&ksk_modulus) as f64,
                get_modulo_value(&ciphertext_modulus) as f64,
            )
        }
    };
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

    let exp_pbs_variance = match lwe_noise_distribution {
        DynamicDistribution::Gaussian(_) => {
            variance_formula::lwe_programmable_bootstrap::pbs_variance_132_bits_security_gaussian(
                lwe_dimension,
                glwe_dimension,
                polynomial_size,
                pbs_decomp_level_count,
                pbs_decomp_base_log,
                get_modulo_value(&ciphertext_modulus) as f64,
                get_modulo_value(&ntt_modulus) as f64,
            )
        }
        DynamicDistribution::TUniform(_) => {
            variance_formula::lwe_programmable_bootstrap::pbs_variance_132_bits_security_tuniform(
                lwe_dimension,
                glwe_dimension,
                polynomial_size,
                pbs_decomp_level_count,
                pbs_decomp_base_log,
                get_modulo_value(&ciphertext_modulus) as f64,
                get_modulo_value(&ntt_modulus) as f64,
            )
        }
    };
    println!(
        "PBS theo variance: {:?} std_dev {:?}/{:?}",
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
    .unaligned_bytes_required();

    buffers.resize(stack_size);

    while msg != 0 {
        msg = msg.wrapping_sub(1);
        for i in 0..nb_tests {
            // re-generate keys
            generate_binary_lwe_secret_key(&mut lwe_sk, &mut rsc.secret_random_generator);
            generate_binary_glwe_secret_key(&mut glwe_sk, &mut rsc.secret_random_generator);
            blwe_sk = glwe_sk.clone().into_lwe_secret_key();

            // re-generate KSK
            generate_lwe_keyswitch_key(
                &blwe_sk,
                &lwe_sk,
                &mut ksk_in_kskmod,
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );
            // re-generate BSK
            par_generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut bsk,
                glwe_noise_distribution,
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

            // encrypt
            let mut ct =
                LweCiphertext::new(0, blwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);
            let mut out_ks_ct = LweCiphertext::new(0, ksk_in_kskmod.output_lwe_size(), ksk_modulus);

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &blwe_sk,
                &mut ct,
                plaintext,
                glwe_noise_distribution,
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
            normality_test_samples.clear();

            for j in 0..nb_pbs_per_test {
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
                keyswitch_lwe_ciphertext(&ksk_in_kskmod, &ct, &mut out_ks_ct);

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
                normality_test_samples.push(torus_diff);
                //println!("added in normality_test_samples: {torus_diff:?}");
                if (j == nb_pbs_per_test - 1) && (test_mode == HpuNoiseMode::Normality) {
                    let sample_set_mean = arithmetic_mean(&normality_test_samples);
                    let sample_set_var = variance(&normality_test_samples);
                    let sample_set_score = sample_set_mean / sample_set_var.get_standard_dev().0
                        * f64::sqrt(normality_test_samples.len() as f64);
                    if (-1.96..1.96).contains(&sample_set_score) {
                        // score is good, it is a success
                        expvalue_score_result.push(0.0);
                    } else {
                        // if score is too high or too low it means expected value is not
                        // near enough from 0, it is a failure
                        expvalue_score_result.push(1.0);
                    }

                    if normality_test_f64(&normality_test_samples, 0.05).null_hypothesis_is_valid {
                        // If we are normal return 0, it's not a failure
                        println!("normality_test_f64 returned 0.0 mean {sample_set_mean:?} var {sample_set_var:?} score {sample_set_score:?}");
                        normality_check_result.push(0.0);
                    } else {
                        println!("normality_test_f64 returned 1.0 mean {sample_set_mean:?} var {sample_set_var:?} score {sample_set_score:?}");
                        normality_check_result.push(1.0);
                    }
                }

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
                if test_mode == HpuNoiseMode::Variance {
                    println!("after pbs (msg={msg},test_nb={i}/{nb_tests},pbs_nb={j}/{nb_pbs_per_test}): plaintext {:?} post pbs {:?} torus_diff {:?}", plaintext.0, decrypted_pbs.0, torus_diff);
                }
                noise_samples[3].push(torus_diff);
            }
        }
    }

    match test_mode {
        HpuNoiseMode::Normality => {
            let normality_failure_rate = arithmetic_mean(&normality_check_result);
            println!("normality failure rate: {normality_failure_rate:?}");
            assert!(
                normality_failure_rate <= 0.065,
                "normality failure rate is not acceptable"
            );
            let expvalue_score_failure_rate = arithmetic_mean(&expvalue_score_result);
            println!("expected value score failure rate: {expvalue_score_failure_rate:?}");
            assert!(
                expvalue_score_failure_rate <= 0.08,
                "expected value score failure rate is not acceptable"
            );
        }
        HpuNoiseMode::Variance => {
            let encryption_variance = variance(&noise_samples[0]);
            let bynorm2_variance = variance(&noise_samples[1]);
            let after_ks_variance = variance(&noise_samples[2]);
            let after_pbs_variance = variance(&noise_samples[3]);
            println!(
                "exp encrypt var {:?} encrypt var {:?} bynorm2 var {} after_ks_variance {} after_pbs_variance {:?}",
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
            let expected_after_ks_variance =
                Variance(expected_bynorm2_variance.0 + exp_add_ks_variance.0);

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

            let after_pbs_errbit =
                params.ct_width as f64 + after_pbs_variance.get_log_standard_dev().0;
            let after_pbs_exp_errbit =
                params.ct_width as f64 + exp_pbs_variance.get_log_standard_dev().0;
            let bynorm2_errbit = params.ct_width as f64 + bynorm2_variance.get_log_standard_dev().0;
            let bynorm2_exp_errbit =
                params.ct_width as f64 + expected_bynorm2_variance.get_log_standard_dev().0;
            let after_ks_errbit =
                params.ct_width as f64 + after_ks_variance.get_log_standard_dev().0;
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
    }
}

// Macro to generate tests for all parameter sets with arguments
macro_rules! create_parameterized_test_hpu{
    ($name:ident { $($param:ident),*  $(,)? }, $max_msg:expr, $nb_test:expr, $nb_pbs:expr, $check_var:expr) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower _ $max_msg _ $nb_test _ $nb_pbs _ $check_var:lower>]() {
                $name($param, $max_msg, $nb_test, $nb_pbs, $check_var)
            }
            )*
        }
    };
}

static NORMALITY_MODE: HpuNoiseMode = HpuNoiseMode::Normality;
static VARIANCE_MODE: HpuNoiseMode = HpuNoiseMode::Variance;

// tests with >= 16k samples for variance check
create_parameterized_test_hpu!(
    hpu_noise_distribution {
        HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_GAUSSIAN,
        HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM,
        HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM_2M128,
    },
    16,
    5,
    200,
    VARIANCE_MODE
);

// tests for checking normality & expected value after KS
create_parameterized_test_hpu!(
    hpu_noise_distribution {
        HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM,
        HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21_132_TUNIFORM_2M128,
    },
    2,
    100,
    160,
    NORMALITY_MODE
);
