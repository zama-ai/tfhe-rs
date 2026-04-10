use super::super::cm_lwe_keyswitch_key_generation::allocate_and_generate_new_cm_lwe_keyswitch_key;
use super::super::cm_params::{CmApParams, CM_PARAM_2_2_MINUS_64};
use super::super::*;
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::commons::test_tools::{
    check_both_ratio_under, normality_test_f64, variance,
};
use crate::core_crypto::experimental::prelude::cm_modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key_cm;
use crate::core_crypto::prelude::misc::torus_modular_diff;
use crate::core_crypto::prelude::*;
use cm_fft64::programmable_bootstrap_cm_lwe_ciphertext;
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 1000;
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

#[test]
fn test_cm_pbs_noise_analysis_1() {
    test_cm_pbs_noise_analysis(&CM_PARAM_2_2_MINUS_64)
}

fn test_cm_pbs_noise_analysis(params: &CmApParams) {
    let cm_dimension = params.cm_dimension;
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let small_lwe_noise_distribution = DynamicDistribution::new_gaussian(
        minimal_lwe_variance_for_132_bits_security_gaussian(params.lwe_dimension, 2_f64.powi(64)),
    );

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let mut rsc = TestResources::new();

    let msg_modulus = 1u64 << params.precision;
    let delta = encoding_with_padding / msg_modulus;

    let f = |x| x;

    let accumulator = cm_generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension,
        cm_dimension,
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    let CmBootstrapKeys {
        small_lwe_sk,
        big_lwe_sk,
        bsk,
        fbsk,
    } = generate_cm_pbs_keys(
        params,
        &mut rsc.encryption_random_generator,
        &mut rsc.secret_random_generator,
    );
    drop(bsk);

    let noises: Vec<Vec<f64>> = (0..5000)
        .into_par_iter()
        .map(move |i| {
            let msg = i % msg_modulus;

            let mut rsc = TestResources::new();

            let plaintexts = PlaintextList::from_container(
                (0..cm_dimension.0).map(|_| msg * delta).collect_vec(),
            );

            let ct = allocate_and_encrypt_new_cm_lwe_ciphertext(
                &small_lwe_sk,
                &plaintexts,
                small_lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.encryption_random_generator,
            );

            let mut output_ct = CmLweCiphertext::new(
                0u64,
                fbsk.output_lwe_dimension(),
                cm_dimension,
                ciphertext_modulus,
            );

            programmable_bootstrap_cm_lwe_ciphertext(&ct, &mut output_ct, &accumulator, &fbsk);

            let decrypted = decrypt_cm_lwe_ciphertext(&big_lwe_sk, &output_ct);

            let mut noises = vec![];
            for (decrypted, plaintext) in decrypted.iter().zip(plaintexts.iter()) {
                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(f(plaintext.0 / delta), decoded);

                let noise = torus_modular_diff(
                    decrypted.0,
                    f(plaintext.0 / delta) * delta,
                    ciphertext_modulus,
                );

                noises.push(noise);
            }
            noises
        })
        .collect();

    let noises_separated: Vec<Vec<f64>> = (0..cm_dimension.0)
        .map(|i| noises.iter().map(|list| list[i]).collect_vec())
        .collect_vec();

    let expected_variance = pbs_variance_132_bits_security_gaussian_impl_2(
        params.lwe_dimension.0 as f64,
        params.glwe_dimension.0 as f64,
        params.polynomial_size.0 as f64,
        (1_u64 << params.base_log_bs.0) as f64,
        params.level_bs.0 as f64,
        2_f64.powi(64),
    );

    println!("expected_variance: {expected_variance:e}");

    for noises in &noises_separated {
        let noises: &[f64] = noises;
        let variance = variance(noises);

        println!("variance: {:?}", variance.0);

        let test_result = normality_test_f64(noises, 0.001);

        assert!(test_result.null_hypothesis_is_valid);

        println!("p_value normality: {}", test_result.p_value);

        assert!(check_both_ratio_under(expected_variance, variance.0, 1.1));
    }
}

pub fn pbs_variance_132_bits_security_gaussian_impl_2(
    input_lwe_dimension: f64,
    output_glwe_dimension: f64,
    output_polynomial_size: f64,
    decomposition_base: f64,
    decomposition_level_count: f64,
    modulus: f64,
) -> f64 {
    input_lwe_dimension
        * (2.06537277069845e-33
            * decomposition_base.powf(2.0)
            * decomposition_level_count
            * output_polynomial_size.powf(2.0)
            * (output_glwe_dimension + 2.0)
            + decomposition_level_count
                * output_polynomial_size
                * ((-0.0497829131652661 * output_glwe_dimension * output_polynomial_size
                    + 5.31469187675068)
                    .exp2()
                    + 16.0 * modulus.powf(-2.0))
                * ((1_f64 / 12.0) * decomposition_base.powf(2.0) + 0.166666666666667)
                * (output_glwe_dimension + 2.0)
            + (1_f64 / 12.0) * modulus.powf(-2.0)
            + (1_f64 / 2.0)
                * output_glwe_dimension
                * output_polynomial_size
                * (0.0208333333333333 * modulus.powf(-2.0)
                    + 0.0416666666666667
                        * decomposition_base.powf(-2.0 * decomposition_level_count))
            + (1_f64 / 24.0) * decomposition_base.powf(-2.0 * decomposition_level_count))
}

#[test]
fn test_cm_pbs_ap_sequence_1() {
    test_cm_pbs_ap_sequence(&CM_PARAM_2_2_MINUS_64)
}

fn test_cm_pbs_ap_sequence(params: &CmApParams) {
    let cm_dimension = params.cm_dimension;
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let small_lwe_noise_distribution = DynamicDistribution::new_gaussian(
        minimal_lwe_variance_for_132_bits_security_gaussian(params.lwe_dimension, 2_f64.powi(64)),
    );

    let big_lwe_noise_distribution =
        DynamicDistribution::new_gaussian(minimal_lwe_variance_for_132_bits_security_gaussian(
            params
                .glwe_dimension
                .to_equivalent_lwe_dimension(params.polynomial_size),
            2_f64.powi(64),
        ));

    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);
    let glwe_dimension = params.glwe_dimension;
    let polynomial_size = params.polynomial_size;

    let mut rsc = TestResources::new();

    let msg_modulus = 1u64 << params.precision;
    let delta = encoding_with_padding / msg_modulus;

    let f = |x| x;

    let accumulator = cm_generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension,
        cm_dimension,
        msg_modulus.cast_into(),
        ciphertext_modulus,
        delta,
        f,
    );

    let CmBootstrapKeys {
        small_lwe_sk,
        big_lwe_sk,
        bsk,
        fbsk,
    } = generate_cm_pbs_keys(
        params,
        &mut rsc.encryption_random_generator,
        &mut rsc.secret_random_generator,
    );
    drop(bsk);

    let cm_lwe_keyswitch_key = allocate_and_generate_new_cm_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        cm_dimension,
        params.base_log_ks,
        params.level_ks,
        small_lwe_noise_distribution,
        ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    let plaintexts = PlaintextList::from_container((0..cm_dimension.0).map(|_| 0).collect_vec());

    let mut ct_big;

    let mut ct_small = CmLweCiphertext::new(
        0u64,
        small_lwe_sk[0].lwe_dimension(),
        cm_dimension,
        ciphertext_modulus,
    );

    let norm2 = 2_f64.powf(params.log_nu).round() as u64;

    let max_nb_zeros_n = (params.max_nb_zeros_n + 1.) as usize;

    let mut encryptions_of_zero = CmLweCiphertextList::new(
        0,
        params.lwe_dimension,
        cm_dimension,
        CmLweCiphertextCount(max_nb_zeros_n),
        ciphertext_modulus,
    );

    let plaintext_list = PlaintextList::new(0, PlaintextCount(cm_dimension.0));

    let plaintext_lists: Vec<_> = (0..max_nb_zeros_n)
        .map(|_| plaintext_list.clone())
        .collect();

    encrypt_cm_lwe_ciphertext_list(
        &small_lwe_sk,
        &mut encryptions_of_zero,
        &plaintext_lists,
        small_lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let log_modulus = polynomial_size.to_blind_rotation_input_modulus_log();

    for _ in 0..NB_TESTS {
        ct_big = allocate_and_encrypt_new_cm_lwe_ciphertext(
            &big_lwe_sk,
            &plaintexts,
            big_lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.encryption_random_generator,
        );

        // depth to bootstrap non clean cts
        for _ in 0..3 {
            for i in ct_big.as_mut() {
                *i = i.wrapping_mul(norm2);
            }

            cm_keyswitch_lwe_ciphertext(&cm_lwe_keyswitch_key, &ct_big, &mut ct_small);

            improve_lwe_ciphertext_modulus_switch_noise_for_binary_key_cm(
                &mut ct_small,
                &encryptions_of_zero,
                params.r_sigma_factor_n,
                params.ms_bound_n,
                params.ms_input_variance_n,
                log_modulus,
            );

            programmable_bootstrap_cm_lwe_ciphertext(&ct_small, &mut ct_big, &accumulator, &fbsk);

            let decrypted = decrypt_cm_lwe_ciphertext(&big_lwe_sk, &ct_big);

            for (decrypted, _plaintext) in decrypted.iter().zip(plaintexts.iter()) {
                let decoded = round_decode(decrypted.0, delta) % msg_modulus;

                assert_eq!(0, decoded);
            }
        }
    }
}
