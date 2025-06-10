use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

pub trait ModulusSwitchedLweCiphertext<Scalar> {
    fn log_modulus(&self) -> CiphertextModulusLog;
    fn lwe_dimension(&self) -> LweDimension;
    fn body(&self) -> Scalar;
    fn mask(&self) -> impl Iterator<Item = Scalar> + '_;
}

pub fn lwe_ciphertext_modulus_switch<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(lwe_in, Scalar::ZERO, log_modulus)
}

/// Performs a ciphertext modulus switch on an LWE ciphertext encrypted under a binary secret key
/// The expectancy of the error is removed from the body before modulus_switching it to reduce the
/// variance of the final noise
///
/// The redundancy is done as [a, a, b, b, b, b, -a, -a]
/// E(0) being mapped around the first case of the LUT, it is not at the center of the a mega case.
///
/// A 1/2 (post MS scale) is removed from the body before modulus_switching it to center the mapping
/// between the modulus switched result and a redundant lookup table.
pub fn lwe_ciphertext_centered_binary_modulus_switch<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    assert!(log_modulus.0 <= Scalar::BITS);
    assert!(log_modulus.0 <= SwitchedScalar::BITS);

    let body_correction_to_add = centered_binary_ms_body_correction_to_add(&lwe_in, log_modulus);

    LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
        lwe_in,
        body_correction_to_add,
        log_modulus,
    )
}

fn centered_binary_ms_body_correction_to_add<Scalar, Cont>(
    lwe_in: &LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> Scalar
where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    let round = |a: Scalar| modulus_switch(a, log_modulus) << (Scalar::BITS - log_modulus.0);

    let mut sum_mask_round_errors = Scalar::ZERO;

    for mask_elem in lwe_in.get_mask().as_ref().iter().copied() {
        let error = round(mask_elem).wrapping_sub(mask_elem);

        sum_mask_round_errors = sum_mask_round_errors.wrapping_add(error);
    }

    let sum_half_mask_round_errors =
        (sum_mask_round_errors.into_signed() / Scalar::Signed::TWO).into_unsigned();

    let half_case = Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1);

    // E(e_MMS) = - sum(mask_round_error / 2)
    // body_centered = body_input - E(e_MMS) - half_case
    // body_centered = body_input + sum(mask_round_error / 2) - half_case
    sum_half_mask_round_errors.wrapping_sub(half_case)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_crypto::algorithms::test::modulus_switch_noise_reduction::{
        measure_noise_added_by_message_preserving_operation, round_mask, TEST_RESOURCES,
    };
    use crate::core_crypto::commons::test_tools::{
        arithmetic_mean, check_both_ratio_under, variance,
    };
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    fn decrypt_modulus_switched_lwe_ciphertext<Scalar, KeyCont>(
        lwe_secret_key: &LweSecretKey<KeyCont>,
        lwe_ciphertext: &impl ModulusSwitchedLweCiphertext<Scalar>,
    ) -> Scalar
    where
        Scalar: UnsignedInteger,
        KeyCont: Container<Element = Scalar>,
    {
        assert!(
            lwe_ciphertext.lwe_dimension() == lwe_secret_key.lwe_dimension(),
            "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
            lwe_ciphertext.lwe_dimension(),
            lwe_secret_key.lwe_dimension()
        );

        let mask = lwe_ciphertext.mask();

        let body = lwe_ciphertext.body();

        let mask_key_dot_product = mask
            .zip(lwe_secret_key.as_ref().iter())
            .fold(Scalar::ZERO, |acc, (left, &right)| {
                acc.wrapping_add(left.wrapping_mul(right))
            });

        body.wrapping_sub(mask_key_dot_product) % (Scalar::ONE << lwe_ciphertext.log_modulus().0)
    }

    #[test]
    fn check_centered_modulus_switch_is_centered() {
        let number_loops = 1_000_000;

        let max_ratio = 1.05;

        assert!(!check_modulus_switch_is_centered(
            |lwe_in, log_modulus| { lwe_ciphertext_modulus_switch(lwe_in, log_modulus) },
            number_loops,
            max_ratio,
        ));

        assert!(check_modulus_switch_is_centered(
            |lwe_in, log_modulus| {
                lwe_ciphertext_centered_binary_modulus_switch(lwe_in, log_modulus)
            },
            number_loops,
            max_ratio,
        ));
    }

    // Verify that p_error_left == p_error_right
    fn check_modulus_switch_is_centered(
        ms: impl Sync
            + Fn(
                LweCiphertext<&[u64]>,
                CiphertextModulusLog,
            ) -> LazyStandardModulusSwitchedLweCiphertext<u64, u64, &[u64]>,
        number_loops: usize,
        max_ratio: f64,
    ) -> bool {
        let lwe_dimension = LweDimension(800);

        let lwe_noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.));

        let ciphertext_modulus = CiphertextModulus::new_native();

        let log_modulus = CiphertextModulusLog(12);

        let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

        for sk_bit in sk.as_mut().iter_mut().step_by(2) {
            *sk_bit = 1;
        }

        // low value increases p_error which helps verify p_error_left == p_error_right
        let half_redundancy = 1;

        let lut_size = 1 << log_modulus.0;

        let (lut_application_left_error, lut_application_right_error): (Vec<bool>, Vec<bool>) = (0
            ..number_loops)
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

                let b = ms(lwe.as_view(), log_modulus);

                let lut_index = decrypt_modulus_switched_lwe_ciphertext(&sk, &b);

                // first mega case is hit by indexes from
                // [0, redundancy/2[ U [N-redundancy/2, N[
                let negative_error = lut_size / 2 <= lut_index;

                let lut_application_left_error =
                    negative_error && (lut_index < lut_size - half_redundancy);

                let lut_application_right_error = !negative_error && half_redundancy <= lut_index;

                (lut_application_left_error, lut_application_right_error)
            })
            .unzip();

        let p_left_error = lut_application_left_error
            .iter()
            .filter(|error| **error)
            .count() as f64
            / number_loops as f64;

        let p_right_error = lut_application_right_error
            .iter()
            .filter(|error| **error)
            .count() as f64
            / number_loops as f64;

        check_both_ratio_under(p_left_error, p_right_error, max_ratio)
    }

    #[test]

    fn check_noise_centered_binary_modulus_switch_noise() {
        let lwe_dimension = LweDimension(800);

        let lwe_noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.));

        let ciphertext_modulus = CiphertextModulus::new_native();

        let log_modulus = CiphertextModulusLog(12);

        let number_loops = 100_000;

        let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

        for sk_bit in sk.as_mut().iter_mut().step_by(2) {
            *sk_bit = 1;
        }

        let sk_average_bit: f64 =
            sk.as_view().into_container().iter().sum::<u64>() as f64 / sk.lwe_dimension().0 as f64;

        println!("sk_average_bit {sk_average_bit:.3}");

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
                    {
                        let centered_binary_ms_body_correction_to_add =
                            centered_binary_ms_body_correction_to_add(&lwe, log_modulus);

                        measure_noise_added_by_message_preserving_operation(&sk, lwe, |ct| {
                            *ct.get_mut_body().data = ct
                                .get_mut_body()
                                .data
                                .wrapping_add(centered_binary_ms_body_correction_to_add);

                            round_mask(ct, log_modulus)
                        })
                    },
                )
            })
            .unzip();

        let ms_error_arithmetic_mean = arithmetic_mean(&ms_errors);

        println!(
            "arithmetic_mean(&ms_errors)                     {}2^{:.2}",
            if ms_error_arithmetic_mean > 0_f64 {
                "+"
            } else {
                "-"
            },
            ms_error_arithmetic_mean.abs().log2()
        );

        let ms_error_improved_arithmetic_mean = arithmetic_mean(&ms_errors_improved);

        println!(
            "arithmetic_mean(&ms_errors_improved)            {}2^{:.2}",
            if ms_error_improved_arithmetic_mean > 0_f64 {
                "+"
            } else {
                "-"
            },
            ms_error_improved_arithmetic_mean.abs().log2()
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

            (lwe_dim + 2.) * modulus * modulus / (96. * poly_size * poly_size)
                + (lwe_dim - 4.) / 48.
        };

        assert!(
            check_both_ratio_under(base_variance, expected_base_variance, 1.03_f64),
            "Expected {expected_base_variance}, got {base_variance}",
        );

        let expected_variance_improved = expected_base_variance / 2.;

        assert!(
            check_both_ratio_under(variance_improved, expected_variance_improved, 1.03_f64),
            "Expected {expected_variance_improved}, got {variance_improved}",
        );
    }
}
