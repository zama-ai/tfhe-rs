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

#[derive(Copy, Clone, Debug)]
pub enum BestCandidate {
    NoAddition,
    AddEncryptionOfZero { index: usize },
}

pub fn choose_candidate_to_improve_modulus_switch_noise<Scalar, C1, C2>(
    lwe: &LweCiphertext<C1>,
    encryptions_of_zero: &LweCiphertextList<C2>,
    r_sigma_factor: f64,
    bound: f64,
    log_modulus: CiphertextModulusLog,
) -> Result<BestCandidate, BestCandidate>
where
    Scalar: UnsignedInteger,
    C1: Container<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    assert_eq!(lwe.lwe_size(), encryptions_of_zero.lwe_size());
    assert_eq!(
        lwe.ciphertext_modulus(),
        encryptions_of_zero.ciphertext_modulus()
    );

    assert_ne!(encryptions_of_zero.lwe_ciphertext_count().0, 0);

    let mask = lwe.get_mask();

    let mask = mask.as_ref();

    let base_measure = measure(
        r_sigma_factor,
        log_modulus,
        mask.iter().copied(),
        *lwe.get_body().data,
    );

    let mut best_candidate = BestCandidate::NoAddition;
    let mut best_measure = base_measure;

    if base_measure <= bound {
        return Ok(best_candidate);
    }

    for (index, encryption_of_zero) in encryptions_of_zero.iter().enumerate() {
        let mask_2 = encryption_of_zero.get_mask();

        let mask_2 = mask_2.as_ref();

        let mask_diff = mask
            .iter()
            .zip_eq(mask_2.iter())
            .map(|(a, b)| a.wrapping_add(*b));

        let body_add = lwe
            .get_body()
            .data
            .wrapping_add(*encryption_of_zero.get_body().data);

        let measure = measure(r_sigma_factor, log_modulus, mask_diff, body_add);

        if measure < best_measure {
            best_measure = measure;
            best_candidate = BestCandidate::AddEncryptionOfZero { index };
        }

        if measure <= bound {
            return Ok(best_candidate);
        }
    }

    Err(best_candidate)
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
    let best_candidate = choose_candidate_to_improve_modulus_switch_noise(
        lwe,
        encryptions_of_zero,
        r_sigma_factor,
        bound,
        log_modulus,
    );

    #[cfg(test)]
    assert!(
        best_candidate.is_ok(),
        "MS noise reduction bound not reached for any candidate"
    );

    let best_candidate = best_candidate.unwrap_or_else(|a| a);

    match best_candidate {
        BestCandidate::NoAddition => {}
        BestCandidate::AddEncryptionOfZero { index } => {
            let encryption_of_zero = encryptions_of_zero.get(index);

            lwe_ciphertext_add_assign(lwe, &encryption_of_zero);
        }
    }
}

#[cfg(test)]
mod tests;
