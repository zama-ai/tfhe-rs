use super::super::test::TestResources;
use super::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::test_tools::{check_both_ratio_under, arithmetic_mean, variance};
use crate::core_crypto::prelude::modulus_switch_noise_reduction::*;
use crate::core_crypto::prelude::{
    allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_lwe_secret_key,
    decrypt_lwe_ciphertext, encrypt_lwe_ciphertext, encrypt_lwe_ciphertext_list,
    LweCiphertextCount, LweCiphertextList, LweCiphertextOwned, LweSecretKey, LweSecretKeyOwned,
    Plaintext, PlaintextCount, PlaintextList, Variance,
};
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use statrs::distribution::{Beta, ContinuousCDF};
use std::cell::RefCell;

#[derive(Copy, Clone)]
struct MsNoiseReductionTestParams {
    pub lwe_dimension: LweDimension,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub modulus_switch_zeros_count: LweCiphertextCount,
    pub bound: NoiseEstimationMeasureBound,
    pub r_sigma_factor: RSigmaFactor,
    pub input_variance: Variance,
    pub log_modulus: CiphertextModulusLog,
    pub expected_individual_check_p_success: f64,
    pub expected_variance_improved: Variance,
    pub target_upper_bound_p_all_fail_log2: f64,
}

const TEST_PARAM: MsNoiseReductionTestParams = MsNoiseReductionTestParams {
    lwe_dimension: LweDimension(918),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    ciphertext_modulus: CiphertextModulus::new_native(),
    modulus_switch_zeros_count: LweCiphertextCount(1449),
    bound: NoiseEstimationMeasureBound(288230376151711744_f64),
    r_sigma_factor: RSigmaFactor(13.179852282053789f64),
    log_modulus: PolynomialSize(2048).to_blind_rotation_input_modulus_log(),
    expected_individual_check_p_success: 0.060923874,
    expected_variance_improved: Variance(1.40546154228955e-6),
    target_upper_bound_p_all_fail_log2: -130.,
    input_variance: Variance(2.63039184094559e-7f64),
};

thread_local! {
    static TEST_RESOURCES: RefCell<TestResources> = {
        RefCell::new(TestResources::new())
    }
}

#[test]
fn improve_modulus_switch_noise_test_individual_check_p_success_test_param() {
    improve_modulus_switch_noise_test_individual_check_p_success(TEST_PARAM);
}

fn improve_modulus_switch_noise_test_individual_check_p_success(
    params: MsNoiseReductionTestParams,
) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
        expected_individual_check_p_success,
        expected_variance_improved: _,
        target_upper_bound_p_all_fail_log2,
        input_variance,
    } = params;

    let modulus = ciphertext_modulus.raw_modulus_float();

    let input_variance = input_variance.get_modular_variance(modulus);

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count.0));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        modulus_switch_zeros_count,
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let total_checks_count = (number_loops * modulus_switch_zeros_count.0) as f64;

    let successes_count: Vec<_> = (0..number_loops)
        .into_par_iter()
        .map(|_| {
            let mut successes_count = 0;

            let lwe = TEST_RESOURCES.with(|rsc| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &sk,
                    Plaintext(0),
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.borrow_mut().encryption_random_generator,
                )
            });

            let mask = lwe.get_mask();

            let mask = mask.as_ref();

            for encryption_of_zero in encryptions_of_zero.iter() {
                let encryption_of_zero_mask = encryption_of_zero.get_mask();

                let encryption_of_zero_mask = encryption_of_zero_mask.as_ref();

                let mask_sum = mask
                    .iter()
                    .zip_eq(encryption_of_zero_mask.iter())
                    .map(|(a, b)| a.wrapping_add(*b));

                let body_sum = lwe
                    .get_body()
                    .data
                    .wrapping_add(*encryption_of_zero.get_body().data);

                let measure = measure_modulus_switch_noise_estimation_for_binary_key(
                    r_sigma_factor,
                    input_variance,
                    log_modulus,
                    mask_sum,
                    body_sum,
                );

                if measure <= bound.0 {
                    successes_count += 1;
                }
            }
            successes_count
        })
        .collect();

    let total_successes_count = successes_count.iter().copied().sum::<usize>() as f64;

    let measured_individual_check_p_success = total_successes_count / total_checks_count;

    println!("measured_individual_check_p_success: {measured_individual_check_p_success}");
    println!("expected_individual_check_p_success: {expected_individual_check_p_success}");

    assert!(
        check_both_ratio_under(measured_individual_check_p_success, expected_individual_check_p_success, 1.1_f64),
        "individual_check_p_success: measured (={measured_individual_check_p_success}) too far from expected (={expected_individual_check_p_success})",
    );

    // Each check follows a Bernoulli distribution
    // We cant to estimate its parameter with a confidence interval
    // We use the Clopper–Pearson interval
    // https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Clopper%E2%80%93Pearson_interval

    let beta_lower_bound = Beta::new(
        total_successes_count,
        total_checks_count - total_successes_count + 1.,
    )
    .unwrap();
    let beta_upper_bound = Beta::new(
        total_successes_count + 1.,
        total_checks_count - total_successes_count,
    )
    .unwrap();

    let target_alpha = 0.001;

    // The 2 following tests are equivalent
    // Having both can help understand the relationship between alpha and upper_bound_p_all_fail
    // variations
    {
        // When using both bounds, the combined alpha is 2 * target_alpha
        let lower_bound_p_success = beta_lower_bound.inverse_cdf(target_alpha);
        let upper_bound_p_success = beta_upper_bound.inverse_cdf(1. - target_alpha);

        println!("lower_bound_p_success {lower_bound_p_success}");
        println!("upper_bound_p_success {upper_bound_p_success}");

        let expected_p_one_fail_log2 = (1. - expected_individual_check_p_success).log2();

        let expected_p_all_fail_log2 =
            expected_p_one_fail_log2 * (modulus_switch_zeros_count.0 as f64 + 1.);

        let upper_bound_p_all_fail_log2 =
            (1. - lower_bound_p_success).log2() * (modulus_switch_zeros_count.0 as f64 + 1.);

        println!("expected_p_all_fail_log2 {expected_p_all_fail_log2}");
        println!("upper_bound_p_all_fail_log2 {upper_bound_p_all_fail_log2}");

        assert!(upper_bound_p_all_fail_log2 < target_upper_bound_p_all_fail_log2);
    }
    {
        let target_upper_bound_p_one_fail_log2 =
            target_upper_bound_p_all_fail_log2 / (modulus_switch_zeros_count.0 as f64 + 1.);

        let target_upper_bound_p_one_fail = 2_f64.powf(target_upper_bound_p_one_fail_log2);

        let target_lower_bound_p_one_success = 1. - target_upper_bound_p_one_fail;

        let alpha_respects_lower_bound = beta_lower_bound.cdf(target_lower_bound_p_one_success);

        println!("alpha_respects_lower_bound {alpha_respects_lower_bound:e}");

        assert!(alpha_respects_lower_bound < target_alpha);
    }
}

#[test]
fn improve_modulus_switch_noise_test_average_number_checks_test_param() {
    improve_modulus_switch_noise_test_average_number_checks(TEST_PARAM);
}

fn improve_modulus_switch_noise_test_average_number_checks(params: MsNoiseReductionTestParams) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
        expected_individual_check_p_success,
        expected_variance_improved: _,
        target_upper_bound_p_all_fail_log2: _,
        input_variance,
    } = params;

    let expected_average_number_checks = 1. / expected_individual_check_p_success;

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let mut number_checks = 0;

    let sk = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut rsc.secret_random_generator,
    );

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count.0));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        modulus_switch_zeros_count,
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let mut lwe = LweCiphertextOwned::new(0, sk.lwe_dimension().to_lwe_size(), ciphertext_modulus);

    for _ in 0..number_loops {
        encrypt_lwe_ciphertext(
            &sk,
            &mut lwe,
            Plaintext(0),
            lwe_noise_distribution,
            &mut rsc.encryption_random_generator,
        );

        let index = match choose_candidate_to_improve_modulus_switch_noise_for_binary_key(
            &lwe,
            &encryptions_of_zero,
            r_sigma_factor,
            bound,
            input_variance,
            log_modulus,
        ) {
            CandidateResult::SatisfiyingBound(candidate) => candidate,
            CandidateResult::BestNotSatisfiyingBound(_) => {
                panic!("No candidate was good enough")
            }
        };

        // Check for NoAddition in all cases
        number_checks += 1;

        match index {
            Candidate::NoAddition => {}
            Candidate::AddEncryptionOfZero { index } => {
                // Number of checks from 0 to index included
                number_checks += index + 1;
            }
        }
    }

    let average_number_checks = number_checks as f64 / number_loops as f64;

    println!("average_number_checks: {average_number_checks}");
    println!("expected_average_number_checks: {expected_average_number_checks}");

    assert!(
        check_both_ratio_under(average_number_checks, expected_average_number_checks, 1.1_f64),
        "average_number_checks: measured (={average_number_checks}) too far from expected (={expected_average_number_checks})",
    );
}

fn round_mask<C: ContainerMut<Element = u64>>(
    ct: &mut LweCiphertext<C>,
    log_modulus: CiphertextModulusLog,
) {
    for a in ct.get_mut_mask().as_mut() {
        *a = round(*a, log_modulus);
    }
}

fn measure_noise_added_by_message_preserving_operation<C1, C2>(
    sk: &LweSecretKey<C1>,
    mut ct: LweCiphertext<C2>,
    message_preserving_operation: impl Fn(&mut LweCiphertext<C2>),
) -> f64
where
    C1: Container<Element = u64>,
    C2: ContainerMut<Element = u64>,
{
    let decrypted_before = decrypt_lwe_ciphertext(sk, &ct);

    message_preserving_operation(&mut ct);

    let decrypted_after = decrypt_lwe_ciphertext(sk, &ct);

    decrypted_after.0.wrapping_sub(decrypted_before.0) as i64 as f64
}

#[test]
fn check_noise_improve_modulus_switch_noise_test_param() {
    check_noise_improve_modulus_switch_noise(TEST_PARAM);
}

fn check_noise_improve_modulus_switch_noise(
    ms_noise_reduction_test_params: MsNoiseReductionTestParams,
) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
        expected_individual_check_p_success: _,
        expected_variance_improved,
        target_upper_bound_p_all_fail_log2: _,
        input_variance,
    } = ms_noise_reduction_test_params;

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

    for sk_bit in sk.as_mut().iter_mut().step_by(2) {
        *sk_bit = 1;
    }

    let sk_average_bit: f64 =
        sk.as_view().into_container().iter().sum::<u64>() as f64 / sk.lwe_dimension().0 as f64;

    println!("sk_average_bit {sk_average_bit:.3}");

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count.0));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        modulus_switch_zeros_count,
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let (ms_errors, ms_errors_improved): (Vec<_>, Vec<_>) = (0..number_loops)
        .into_par_iter()
        .map(|_| {
            let lwe = TEST_RESOURCES.with(|rsc| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &sk,
                    Plaintext(0),
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.borrow_mut().encryption_random_generator,
                )
            });

            (
                measure_noise_added_by_message_preserving_operation(&sk, lwe.clone(), |ct| {
                    round_mask(ct, log_modulus)
                }),
                measure_noise_added_by_message_preserving_operation(&sk, lwe, |ct| {
                    improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
                        ct,
                        &encryptions_of_zero,
                        r_sigma_factor,
                        bound,
                        input_variance,
                        log_modulus,
                    );

                    round_mask(ct, log_modulus)
                }),
            )
        })
        .unzip();

    println!(
        "arithmetic_mean(&ms_errors)                     {}2^{:.2}",
        if arithmetic_mean(&ms_errors) > 0_f64 {
            "+"
        } else {
            "-"
        },
        arithmetic_mean(&ms_errors).abs().log2()
    );

    println!(
        "arithmetic_mean(&ms_errors_improved)            {}2^{:.2}",
        if arithmetic_mean(&ms_errors_improved) > 0_f64 {
            "+"
        } else {
            "-"
        },
        arithmetic_mean(&ms_errors_improved).abs().log2()
    );

    let base_variance = variance(&ms_errors).0;

    println!(
        "variance(&ms_errors),                    2^{:.2}",
        base_variance.log2(),
    );

    let variance_improved = variance(&ms_errors_improved).0;

    println!(
        "variance(&ms_errors_improved)            2^{:.2}, ratio: {:.3}",
        variance_improved.log2(),
        variance_improved / base_variance,
    );

    let modulus = ciphertext_modulus.raw_modulus_float();

    let expected_base_variance = {
        let lwe_dim = lwe_dimension.0 as f64;

        let poly_size = 2_f64.powi((log_modulus.0 - 1) as i32);

        (lwe_dim + 2.) * modulus * modulus / (96. * poly_size * poly_size) + (lwe_dim - 4.) / 48.
    };

    assert!(
        check_both_ratio_under(base_variance, expected_base_variance, 1.03_f64),
        "Expected {expected_base_variance}, got {base_variance}",
    );

    let expected_variance_improved = Variance(expected_variance_improved.0 - input_variance.0)
        .get_modular_variance(modulus)
        .value;

    assert!(
        check_both_ratio_under(variance_improved, expected_variance_improved, 1.03_f64),
        "Expected {expected_variance_improved}, got {variance_improved}",
    );
}
