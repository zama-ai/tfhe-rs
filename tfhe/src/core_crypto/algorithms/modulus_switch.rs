use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

/// Represent any kind of LWE ciphertext after a modulus switch operation.
///
/// This may be used as an input to the blind rotatation.
pub trait ModulusSwitchedLweCiphertext<Scalar> {
    fn log_modulus(&self) -> CiphertextModulusLog;
    fn lwe_dimension(&self) -> LweDimension;
    fn body(&self) -> Scalar;
    fn mask(&self) -> impl ExactSizeIterator<Item = Scalar> + '_;
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

    let mut sum_half_mask_round_errors = Scalar::ZERO;

    let mut sum_halving_errors_doubled = Scalar::Signed::ZERO;

    for mask_elem in lwe_in.get_mask().as_ref().iter().copied() {
        let error = round(mask_elem).wrapping_sub(mask_elem);

        let signed_error = error.into_signed();

        let half_error = signed_error / Scalar::Signed::TWO;

        // Dividing by 2 can add an error where |error| <= 1/2 in each run of the loop
        // Combined, they can add up to more than 1 (in the mod 2^64 torus)
        // Thus we compute this combined error to reduce it to less than 1/2
        // half_error = half_error_theoretical + halving_error_doubled/2
        // where half_error_theoretical * 2 = signed_error
        let halving_error_doubled = Scalar::Signed::TWO * half_error - signed_error;

        sum_half_mask_round_errors =
            sum_half_mask_round_errors.wrapping_add(half_error.into_unsigned());

        sum_halving_errors_doubled += halving_error_doubled;
    }

    let sum_halving_errors = (sum_halving_errors_doubled / Scalar::Signed::TWO).into_unsigned();

    // sum(half_error_theoretical) = sum(half_error) - sum(halving_error_doubled)/2
    let sum_half_mask_round_errors = sum_half_mask_round_errors.wrapping_sub(sum_halving_errors);

    let half_case = Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1);

    // E(e_MMS) = - sum(mask_round_error / 2)
    // body_centered = body_input - E(e_MMS) - half_case
    // body_centered = body_input + sum(mask_round_error / 2) - half_case
    // body_correction_to_add = sum(mask_round_error / 2) - half_case
    sum_half_mask_round_errors.wrapping_sub(half_case)
}

// ============== Noise measurement trait implementations ============== //
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult, AllocateStandardModSwitchResult,
    CenteredBinaryShiftedStandardModSwitch, StandardModSwitch,
};

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> AllocateStandardModSwitchResult
    for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        // We will mod switch but we keep the current modulus as the noise is interesting in the
        // context of the input modulus
        Self::Output::new(Scalar::ZERO, self.lwe_size(), self.ciphertext_modulus())
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        OutputCont: ContainerMut<Element = Scalar>,
    > StandardModSwitch<LweCiphertext<OutputCont>> for LweCiphertext<InputCont>
{
    type SideResources = ();

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut LweCiphertext<OutputCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        assert!(self
            .ciphertext_modulus()
            .is_compatible_with_native_modulus());
        assert_eq!(self.lwe_size(), output.lwe_size());
        // Mod switched but the noise is to be interpreted with respect to the input modulus, as
        // strictly the operation adding the noise is the rounding under the original modulus
        assert_eq!(self.ciphertext_modulus(), output.ciphertext_modulus());

        for (inp, out) in self.as_ref().iter().zip(output.as_mut().iter_mut()) {
            let msed = modulus_switch(*inp, output_modulus_log);
            // Shift in MSBs to match the power of 2 encoding in core
            *out = msed << (Scalar::BITS - output_modulus_log.0);
        }
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    AllocateCenteredBinaryShiftedStandardModSwitchResult for LweCiphertext<C>
{
    type Output = LweCiphertextOwned<Scalar>;
    type SideResources = ();

    fn allocate_centered_binary_shifted_standard_mod_switch_result(
        &self,
        _side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        // We will mod switch but we keep the current modulus as the noise is interesting in the
        // context of the input modulus
        Self::Output::new(Scalar::ZERO, self.lwe_size(), self.ciphertext_modulus())
    }
}

impl<
        Scalar: UnsignedInteger,
        InputCont: Container<Element = Scalar>,
        OutputCont: ContainerMut<Element = Scalar>,
    > CenteredBinaryShiftedStandardModSwitch<LweCiphertext<OutputCont>>
    for LweCiphertext<InputCont>
{
    type SideResources = ();

    fn centered_binary_shifted_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut LweCiphertext<OutputCont>,
        _side_resources: &mut Self::SideResources,
    ) {
        assert!(self
            .ciphertext_modulus()
            .is_compatible_with_native_modulus());
        assert_eq!(self.lwe_size(), output.lwe_size());
        // Mod switched but the noise is to be interpreted with respect to the input modulus, as
        // strictly the operation adding the noise is the rounding under the original modulus
        assert_eq!(self.ciphertext_modulus(), output.ciphertext_modulus());

        let lwe_mod_switched = lwe_ciphertext_centered_binary_modulus_switch::<Scalar, Scalar, _>(
            self.as_view(),
            output_modulus_log,
        );

        let (mut out_mask, out_body) = output.get_mut_mask_and_body();

        for (inp, out) in lwe_mod_switched.mask().zip(out_mask.as_mut().iter_mut()) {
            *out = inp << (Scalar::BITS - output_modulus_log.0);
        }
        *out_body.data = lwe_mod_switched.body() << (Scalar::BITS - output_modulus_log.0);
    }
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

    #[test]
    fn test_ms_halving_correction() {
        let ciphertext_modulus = CiphertextModulus::new_native();
        let log_modulus = CiphertextModulusLog(12);

        // for both mask element, mask_round_error = -1
        // body_correction_to_add = sum(mask_round_error / 2) - half_case
        // body_correction_to_add = -1 - half_case
        let lwe = LweCiphertext::from_container(vec![1_u64, 1, 0], ciphertext_modulus);

        let half_case = 1_u64 << (64 - log_modulus.0 - 1);

        let expected_body_correction_to_add = 1.wrapping_neg().wrapping_sub(half_case);

        let msed_lwe = lwe_ciphertext_centered_binary_modulus_switch::<u64, u64, _>(
            lwe.as_view(),
            log_modulus,
        );

        let (_lwe_in, body_correction_to_add_before_switching, _log_modulus) =
            msed_lwe.into_raw_parts();

        assert_eq!(
            body_correction_to_add_before_switching,
            expected_body_correction_to_add,
        );
    }

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

        // lwe_ciphertext_modulus_switch does do half case correction so should fail this check
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

                let msed_lwe = ms(lwe.as_view(), log_modulus);

                let lut_index = decrypt_modulus_switched_lwe_ciphertext(&sk, &msed_lwe);

                // lut indexes are modular (modulo 2^log_modulus)
                // (modulus = 2 * polynomial_size)
                // We do:
                // - map [0, 2^log_modulus[ to [0, 2^64[
                // - go from unsigned to signed modulo 2^64 (with into_signed)
                // - map back [0, 2^64[ to [0, 2^log_modulus[
                // In the end, we have a signed index
                let lut_index_signed =
                    (lut_index << (64 - log_modulus.0)).into_signed() >> (64 - log_modulus.0);

                // The lut case goes from [-half_redundancy, half_redundancy[
                // It contains redundancy(=2*half_redundancy) elements and is not centered around 0
                let lut_application_left_error = lut_index_signed < -half_redundancy;

                let lut_application_right_error = half_redundancy <= lut_index_signed;

                (lut_application_left_error, lut_application_right_error)
            })
            .unzip();

        let left_error_count = lut_application_left_error
            .iter()
            .filter(|error| **error)
            .count();

        let right_error_count = lut_application_right_error
            .iter()
            .filter(|error| **error)
            .count();

        let p_left_error = left_error_count as f64 / number_loops as f64;

        let p_right_error = right_error_count as f64 / number_loops as f64;

        println!("p_left_error={p_left_error}, p_right_error={p_right_error}");

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
