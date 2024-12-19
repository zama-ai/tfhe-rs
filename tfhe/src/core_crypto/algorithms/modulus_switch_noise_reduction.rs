use super::lwe_ciphertext_add_assign;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::traits::{Container, ContainerMut, UnsignedInteger};
use crate::core_crypto::entities::{LweCiphertext, LweCiphertextList};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::{CiphertextModulusLog, ContiguousEntityContainer};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct RSigmaFactor(pub f64);

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct NoiseEstimationMeasureBound(pub f64);

pub(crate) fn round<Scalar: UnsignedInteger>(
    input: Scalar,
    log_modulus: CiphertextModulusLog,
) -> Scalar {
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

fn measure_modulus_switch_noise_expectancy_variance_for_binary_key<Scalar: UnsignedInteger>(
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

fn measure_noise_estimation<Scalar: UnsignedInteger>(
    r_sigma_factor: RSigmaFactor,
    log_modulus: CiphertextModulusLog,
    masks: impl Iterator<Item = Scalar>,
    body: Scalar,
) -> f64 {
    let NoiseEstimation {
        expectancy,
        variance,
    } = measure_modulus_switch_noise_expectancy_variance_for_binary_key(masks, body, log_modulus);

    let std_dev = variance.sqrt();

    expectancy.abs() + std_dev * r_sigma_factor.0
}

#[derive(Copy, Clone, Debug)]
pub enum Candidate {
    NoAddition,
    AddEncryptionOfZero { index: usize },
}

pub enum CandidateResult {
    SatisfiyingBound(Candidate),
    BestNotSatisfiyingBound(Candidate),
}

pub fn choose_candidate_to_improve_modulus_switch_noise_for_binary_key<Scalar, C1, C2>(
    lwe: &LweCiphertext<C1>,
    encryptions_of_zero: &LweCiphertextList<C2>,
    r_sigma_factor: RSigmaFactor,
    bound: NoiseEstimationMeasureBound,
    log_modulus: CiphertextModulusLog,
) -> CandidateResult
where
    Scalar: UnsignedInteger,
    C1: Container<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    assert_eq!(
        lwe.lwe_size(),
        encryptions_of_zero.lwe_size(),
        "input lwe size (={}) != encryptions of zero lwe size (={})",
        lwe.lwe_size().0,
        encryptions_of_zero.lwe_size().0,
    );
    assert_eq!(
        lwe.ciphertext_modulus(),
        encryptions_of_zero.ciphertext_modulus(),
        "input ciphertext_modulus (={}) != encryptions of zero ciphertext_modulus (={})",
        lwe.ciphertext_modulus(),
        encryptions_of_zero.ciphertext_modulus(),
    );
    assert_ne!(
        encryptions_of_zero.lwe_ciphertext_count().0,
        0,
        "Expected at least one encryption of zero"
    );

    let mask = lwe.get_mask();

    let mask = mask.as_ref();

    let base_measure = measure_noise_estimation(
        r_sigma_factor,
        log_modulus,
        mask.iter().copied(),
        *lwe.get_body().data,
    );

    let mut best_candidate = Candidate::NoAddition;
    let mut best_measure = base_measure;

    if base_measure <= bound.0 {
        return CandidateResult::SatisfiyingBound(best_candidate);
    }

    for (index, encryption_of_zero) in encryptions_of_zero.iter().enumerate() {
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

        let measure = measure_noise_estimation(r_sigma_factor, log_modulus, mask_sum, body_sum);

        if measure < best_measure {
            best_measure = measure;
            best_candidate = Candidate::AddEncryptionOfZero { index };
        }

        if measure <= bound.0 {
            return CandidateResult::SatisfiyingBound(best_candidate);
        }
    }

    CandidateResult::BestNotSatisfiyingBound(best_candidate)
}

// Based on https://eprint.iacr.org/2024/1718.pdf
pub fn improve_lwe_ciphertext_modulus_switch_noise_for_binary_key<Scalar, C1, C2>(
    lwe: &mut LweCiphertext<C1>,
    encryptions_of_zero: &LweCiphertextList<C2>,
    r_sigma_factor: RSigmaFactor,
    bound: NoiseEstimationMeasureBound,
    log_modulus: CiphertextModulusLog,
) where
    Scalar: UnsignedInteger,
    C1: ContainerMut<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    let candidate = choose_candidate_to_improve_modulus_switch_noise_for_binary_key(
        lwe,
        encryptions_of_zero,
        r_sigma_factor,
        bound,
        log_modulus,
    );

    #[cfg(test)]
    assert!(
        matches!(candidate, CandidateResult::SatisfiyingBound(_)),
        "MS noise reduction bound not reached for any candidate"
    );

    let candidate = match candidate {
        CandidateResult::SatisfiyingBound(candidate) => candidate,
        CandidateResult::BestNotSatisfiyingBound(candidate) => candidate,
    };

    match candidate {
        Candidate::NoAddition => {}
        Candidate::AddEncryptionOfZero { index } => {
            let encryption_of_zero = encryptions_of_zero.get(index);

            lwe_ciphertext_add_assign(lwe, &encryption_of_zero);
        }
    }
}
