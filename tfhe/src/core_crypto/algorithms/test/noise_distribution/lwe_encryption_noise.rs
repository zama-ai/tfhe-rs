use super::*;
use crate::core_crypto::algorithms::misc::check_clear_content_respects_mod;
use crate::core_crypto::commons::test_tools::{
    modular_distance, modular_distance_custom_mod, torus_modular_diff, variance,
};
use csv::Writer;
use std::io;

// This is 1 / 16 which is exactly representable in an f64 (even an f32)
// 1 / 32 is too strict and fails the tests
const RELATIVE_TOLERANCE: f64 = 0.0625;

const NB_TESTS: usize = 1000;
const NB_HPU_TESTS: usize = 4;
const NB_PBS: usize = 10;

fn lwe_encrypt_decrypt_noise_distribution_custom_mod<Scalar: UnsignedTorus + CastInto<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let expected_variance = lwe_noise_distribution.gaussian_std_dev().get_variance();

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &lwe_sk,
                &mut ct,
                plaintext,
                lwe_noise_distribution,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_diff = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_diff);
        }
    }

    let measured_variance = variance(&noise_samples);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(lwe_encrypt_decrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_SOLINAS_U64,
    TEST_PARAMS_3_BITS_63_U64
});

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
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_modular_std_dev: StandardDev,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus_log: CiphertextModulusLog,
    pub ct_width: usize,
    pub ksk_width: usize,
    pub norm2: u64,
    pub ntt_modulus: u64,
}

pub const HPU_TEST_PARAMS_4_BITS_HPU_44_KS_21: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(742),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(1.2597809688976277e-05),
    glwe_modular_std_dev: StandardDev(2.2737367544323206e-13),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(7),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(20),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 44,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 17592186028033,
};

pub const HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21: HpuTestParams = HpuTestParams {
    lwe_dimension: LweDimension(786),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(5.314123935599821e-06),
    glwe_modular_std_dev: StandardDev(9.1881734381394e-16),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(8),
    ks_base_log: DecompositionBaseLog(2),
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(24),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 21,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

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
    pfks_level: DecompositionLevelCount(1),
    pfks_base_log: DecompositionBaseLog(23),
    pfks_modular_std_dev: StandardDev(0.00000000000000029403601535432533),
    cbs_level: DecompositionLevelCount(0),
    cbs_base_log: DecompositionBaseLog(0),
    message_modulus_log: CiphertextModulusLog(4),
    ct_width: 64,
    ksk_width: 64,
    norm2: 5,
    ntt_modulus: 18446744069414584321,
};

pub fn get_modulo_value<T: UnsignedInteger>(modulus: &CiphertextModulus<T>) -> u128 {
    let mod_val: u128 = match modulus.is_native_modulus() {
        true => {
            let converted: CiphertextModulus<u128> = modulus.try_to().unwrap();
            u128::cast_from(converted.get_custom_modulus())
        }
        false => u128::cast_from(modulus.get_custom_modulus()),
    };
    mod_val
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

    //let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let num_samples = NB_PBS * NB_HPU_TESTS * (msg as usize);
    let mut noise_samples = vec![Vec::with_capacity(num_samples); 4];
    println!("ciphertext_modulus {:?} message_modulus_log {:?} encoding_with_padding {} expected_variance {:?} msg_modulus {} msg {} delta {}",
        ciphertext_modulus,
        message_modulus_log,
        encoding_with_padding,
        expected_variance,
        msg_modulus,
        msg,
        delta);

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

    use crate::core_crypto::commons::math::ntt::ntt64::Ntt64;

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

    let stack_size = programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ntt,
    )
    .unwrap()
    .try_unaligned_bytes_required()
    .unwrap();

    buffers.resize(stack_size);

    par_convert_standard_lwe_bootstrap_key_to_ntt64(&bsk, &mut nbsk);

    assert!(check_encrypted_content_respects_mod(
        &*bsk,
        ciphertext_modulus
    ));

    drop(bsk);

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
            println!(
                "after decryption: plaintext {:?} decrypted {:?} torus_diff {:?}",
                plaintext.0, decrypted.0, torus_diff
            );
            noise_samples[0].push(torus_diff);

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
                println!(
                    "after by norm2: plaintext {:?} bynorm2 {:?} torus_diff {:?}",
                    0, decrypted_prodnorm2.0, torus_diff
                );
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
                let torus_diff: f64;
                if cm_f == ksm_f {
                    torus_diff =
                        torus_modular_diff(plaintext.0, decrypted_after_ks.0, ciphertext_modulus);
                    println!(
                        "after ks {} / {} vs {}",
                        torus_diff, plaintext.0, decrypted_after_ks.0
                    );
                } else {
                    let decrypted_after_ks_modswitched =
                        decrypted_after_ks.0 * ((cm_f / ksm_f) as u64);
                    torus_diff = torus_modular_diff(
                        plaintext.0,
                        decrypted_after_ks_modswitched,
                        ciphertext_modulus,
                    );
                    println!(
                        "after ks {} / {} vs {}*CT_MOD/KS_MOD={}",
                        torus_diff,
                        plaintext.0,
                        decrypted_after_ks.0,
                        decrypted_after_ks_modswitched
                    );
                }

                noise_samples[2].push(torus_diff);

                // Compute PBS with NTT
                programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
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
        "exp var {:?} encryp var {:?} bynorm2 var {} after_ks_variance {} after_pbs_variance {:?}",
        expected_variance.0,
        encryption_variance.0,
        bynorm2_variance.0,
        after_ks_variance.0,
        after_pbs_variance.0
    );

    let mut wtr = csv::Writer::from_writer(io::stdout());
    let _ = wtr.write_record(&[
        "data type",
        "encrypt exp",
        "encrypt",
        "post *norm2",
        "post KS",
        "post KS Delta",
        "post PBS",
        "post PBS Delta",
    ]);
    let _ = wtr.write_record(&[
        "variances",
        expected_variance.0.to_string().as_str(),
        encryption_variance.0.to_string().as_str(),
        bynorm2_variance.0.to_string().as_str(),
        after_ks_variance.0.to_string().as_str(),
        (after_ks_variance.0 - bynorm2_variance.0)
            .to_string()
            .as_str(),
        after_pbs_variance.0.to_string().as_str(),
        (bynorm2_variance.0 - after_pbs_variance.0)
            .to_string()
            .as_str(),
    ]);
    let _ = wtr.write_record(&[
        "std_dev",
        expected_variance.get_standard_dev().0.to_string().as_str(),
        encryption_variance
            .get_standard_dev()
            .0
            .to_string()
            .as_str(),
        bynorm2_variance.get_standard_dev().0.to_string().as_str(),
        after_ks_variance.get_standard_dev().0.to_string().as_str(),
        (after_ks_variance.get_standard_dev().0 - bynorm2_variance.get_standard_dev().0)
            .to_string()
            .as_str(),
        after_pbs_variance.get_standard_dev().0.to_string().as_str(),
        (bynorm2_variance.get_standard_dev().0 - after_pbs_variance.get_standard_dev().0)
            .to_string()
            .as_str(),
    ]);
    let _ = wtr.write_record(&[
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
        (after_ks_variance.get_log_standard_dev().0 - bynorm2_variance.get_log_standard_dev().0)
            .to_string()
            .as_str(),
        (after_pbs_variance.get_log_standard_dev().0 + params.ct_width as f64)
            .to_string()
            .as_str(),
        (bynorm2_variance.get_log_standard_dev().0 - after_pbs_variance.get_log_standard_dev().0)
            .to_string()
            .as_str(),
    ]);

    // does not compare to expected encryption variance as it needs lots of sample to be valid
    // and has already been done in many other TFHErs tests
    //let var_abs_diff = (expected_variance.0 - encryption_variance.0).abs();
    //let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    //assert!(
    //    var_abs_diff < tolerance_threshold,
    //    "Absolute difference for variance: {var_abs_diff}, \
    //    tolerance threshold: {tolerance_threshold}, \
    //    got variance: {encryption_variance:?}, \
    //    expected variance: {expected_variance:?}"
    //);
}

create_parameterized_test!(hpu_noise_distribution {
    HPU_TEST_PARAMS_4_BITS_NATIVE_U64,
    HPU_TEST_PARAMS_4_BITS_HPU_44_KS_21,
    HPU_TEST_PARAMS_4_BITS_HPU_64_KS_21,
});

fn lwe_compact_public_key_encryption_expected_variance(
    input_noise: impl DispersionParameter,
    lwe_dimension: LweDimension,
) -> Variance {
    let input_variance = input_noise.get_variance();
    Variance(input_variance.0 * (lwe_dimension.to_lwe_size().0 as f64))
}

#[test]
fn test_variance_increase_cpk_formula() {
    let predicted_variance = lwe_compact_public_key_encryption_expected_variance(
        StandardDev(2.0_f64.powi(39)),
        LweDimension(1024),
    );

    assert!(
        (predicted_variance.get_standard_dev().0.log2() - 44.000704097196405f64).abs()
            < f64::EPSILON
    );
}

fn lwe_compact_public_encrypt_noise_distribution_custom_mod<
    Scalar: UnsignedTorus + CastInto<usize>,
>(
    params: ClassicTestParams<Scalar>,
) {
    let lwe_dimension = LweDimension(params.polynomial_size.0);
    let glwe_noise_distribution = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let glwe_variance = glwe_noise_distribution.gaussian_std_dev().get_variance();

    let expected_variance =
        lwe_compact_public_key_encryption_expected_variance(glwe_variance, lwe_dimension);

    let mut rsc = TestResources::new();

    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = encoding_with_padding / msg_modulus;

    let num_samples = NB_TESTS * <Scalar as CastInto<usize>>::cast_into(msg);
    let mut noise_samples = Vec::with_capacity(num_samples);

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let pk = allocate_and_generate_new_lwe_compact_public_key(
                &lwe_sk,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext_with_compact_public_key(
                &pk,
                &mut ct,
                plaintext,
                glwe_noise_distribution,
                glwe_noise_distribution,
                &mut rsc.secret_random_generator,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_encrypted_content_respects_mod(
                &ct,
                ciphertext_modulus
            ));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!(msg, decoded);

            let torus_diff = torus_modular_diff(plaintext.0, decrypted.0, ciphertext_modulus);
            noise_samples.push(torus_diff);
        }
    }

    let measured_variance = variance(&noise_samples);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
        tolerance threshold: {tolerance_threshold}, \
        got variance: {measured_variance:?}, \
        expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(lwe_compact_public_encrypt_noise_distribution_custom_mod {
    TEST_PARAMS_4_BITS_NATIVE_U64
});

fn random_noise_roundtrip<Scalar: UnsignedTorus + CastInto<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let mut rsc = TestResources::new();
    let noise = params.glwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let encryption_rng = &mut rsc.encryption_random_generator;

    assert!(matches!(noise, DynamicDistribution::Gaussian(_)));

    let expected_variance = noise.gaussian_std_dev().get_variance();

    let num_outputs = 100_000;

    let mut output: Vec<_> = vec![Scalar::ZERO; num_outputs];

    encryption_rng.fill_slice_with_random_noise_from_distribution_custom_mod(
        &mut output,
        noise,
        ciphertext_modulus,
    );

    assert!(check_clear_content_respects_mod(
        &output,
        ciphertext_modulus
    ));

    for val in output.iter().copied() {
        if ciphertext_modulus.is_native_modulus() {
            let float_torus = val.into_torus();
            let from_torus = Scalar::from_torus(float_torus);
            assert!(
                modular_distance(val, from_torus)
                    < (Scalar::ONE << (Scalar::BITS.saturating_sub(f64::MANTISSA_DIGITS as usize))),
                "val={val}, from_torus={from_torus}, float_torus={float_torus}"
            );
        } else {
            let custom_modulus_as_scalar: Scalar =
                ciphertext_modulus.get_custom_modulus().cast_into();

            let float_torus = val.into_torus_custom_mod(custom_modulus_as_scalar);
            let from_torus = Scalar::from_torus_custom_mod(float_torus, custom_modulus_as_scalar);
            assert!(from_torus < custom_modulus_as_scalar);
            assert!(
                modular_distance_custom_mod(val, from_torus, custom_modulus_as_scalar)
                    < (Scalar::ONE << (Scalar::BITS.saturating_sub(f64::MANTISSA_DIGITS as usize))),
                "val={val}, from_torus={from_torus}, float_torus={float_torus}"
            );
        }
    }

    let output: Vec<_> = output
        .into_iter()
        .map(|x| torus_modular_diff(Scalar::ZERO, x, ciphertext_modulus))
        .collect();

    let measured_variance = variance(&output);
    let var_abs_diff = (expected_variance.0 - measured_variance.0).abs();
    let tolerance_threshold = RELATIVE_TOLERANCE * expected_variance.0;
    assert!(
        var_abs_diff < tolerance_threshold,
        "Absolute difference for variance: {var_abs_diff}, \
            tolerance threshold: {tolerance_threshold}, \
            got variance: {measured_variance:?}, \
            expected variance: {expected_variance:?}"
    );
}

create_parameterized_test!(random_noise_roundtrip {
    TEST_PARAMS_4_BITS_NATIVE_U64,
    TEST_PARAMS_3_BITS_SOLINAS_U64,
    TEST_PARAMS_3_BITS_63_U64
});
