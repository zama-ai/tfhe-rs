use super::lwe_ciphertext_add_assign;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::traits::{Container, ContainerMut, UnsignedInteger};
use crate::core_crypto::entities::{LweCiphertext, LweCiphertextList};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::{CiphertextModulusLog, ContiguousEntityContainer};
use itertools::Itertools;

fn round<Scalar: UnsignedInteger>(input: Scalar, log_modulus: CiphertextModulusLog) -> Scalar {
    modulus_switch(input, log_modulus) << (Scalar::BITS - log_modulus.0)
}

fn round_error<Scalar: UnsignedInteger>(
    input: Scalar,
    log_modulus: CiphertextModulusLog,
) -> Scalar {
    let rounded = round(input, log_modulus);

    // rounded = input + round_error
    rounded.wrapping_sub(input)
}

fn round_error_float<Scalar: UnsignedInteger>(
    input: Scalar,
    log_modulus: CiphertextModulusLog,
) -> f64 {
    round_error(input, log_modulus).into_signed().cast_into()
}

#[derive(Copy, Clone)]
struct NoiseEstimation {
    expectancy: f64,
    variance: f64,
}

fn measure_modulus_switch_noise_expectancy_variance<Scalar: UnsignedInteger>(
    masks: impl Iterator<Item = Scalar>,
    body: Scalar,
    log_modulus: CiphertextModulusLog,
) -> NoiseEstimation {
    let mut sum_mask_errors = 0_f64;
    let mut sum_square_mask_errors = 0_f64;

    for mask in masks {
        let error = round_error_float(mask, log_modulus);

        sum_mask_errors += error;
        sum_square_mask_errors += error * error;
    }

    let body_error = round_error_float(body, log_modulus);

    let expectancy = body_error - sum_mask_errors / 2_f64;

    let variance = sum_square_mask_errors / 4_f64;

    NoiseEstimation {
        expectancy,
        variance,
    }
}

fn measure<Scalar: UnsignedInteger>(
    r_sigma_factor: f64,
    log_modulus: CiphertextModulusLog,
    masks: impl Iterator<Item = Scalar>,
    body: Scalar,
) -> f64 {
    let NoiseEstimation {
        expectancy,
        variance,
    } = measure_modulus_switch_noise_expectancy_variance(masks, body, log_modulus);

    let std_dev = variance.sqrt();

    expectancy.abs() + std_dev * r_sigma_factor
}

pub fn choose_candidate_to_improve_modulus_switch_noise<Scalar, C1, C2>(
    lwe: &LweCiphertext<C1>,
    encryptions_of_zero: &LweCiphertextList<C2>,
    r_sigma_factor: f64,
    bound: f64,
    log_modulus: CiphertextModulusLog,
) -> Result<usize, usize>
where
    Scalar: UnsignedInteger,
    C1: Container<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    assert_eq!(lwe.lwe_size(), encryptions_of_zero.lwe_size());
    assert_ne!(encryptions_of_zero.lwe_ciphertext_count().0, 0);

    let mut best_index = 0;

    let mut best_measure = f64::INFINITY;

    for (index, encryption_of_zero) in encryptions_of_zero.iter().enumerate() {
        let mask = lwe.get_mask();

        let mask_2 = encryption_of_zero.get_mask();

        let mask_diff = mask
            .as_ref()
            .iter()
            .zip_eq(mask_2.as_ref().iter())
            .map(|(a, b)| a.wrapping_add(*b));

        let measure = measure(
            r_sigma_factor,
            log_modulus,
            mask_diff,
            lwe.get_body()
                .data
                .wrapping_add(*encryption_of_zero.get_body().data),
        );

        if measure < best_measure {
            best_measure = measure;
            best_index = index;
        }

        if measure <= bound {
            return Ok(index);
        }
    }

    Err(best_index)
}

pub fn improve_modulus_switch_noise<Scalar, C1, C2>(
    lwe: &mut LweCiphertext<C1>,
    encryptions_of_zero: &LweCiphertextList<C2>,
    r_sigma_factor: f64,
    bound: f64,
    log_modulus: CiphertextModulusLog,
) where
    Scalar: UnsignedInteger,
    C1: ContainerMut<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    let index = choose_candidate_to_improve_modulus_switch_noise(
        lwe,
        encryptions_of_zero,
        r_sigma_factor,
        bound,
        log_modulus,
    );

    #[cfg(test)]
    assert!(
        index.is_ok(),
        "MS noise reduction bound not reached for any candidate"
    );

    let index = index.unwrap_or_else(|a| a);

    let encryption_of_zero = encryptions_of_zero.get(index);

    lwe_ciphertext_add_assign(lwe, &encryption_of_zero);
}
