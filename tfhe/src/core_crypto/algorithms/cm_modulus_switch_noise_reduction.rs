use crate::core_crypto::commons::dispersion::{ModularVariance, Variance};
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{NoiseEstimationMeasureBound, RSigmaFactor};
use crate::core_crypto::commons::traits::{Container, ContainerMut, UnsignedInteger};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::{CmLweCiphertext, CmLweCiphertextList};
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::{
    CiphertextModulus, CiphertextModulusLog, ContiguousEntityContainer, DispersionParameter,
};
use itertools::Itertools;

/// Only works on power of 2 moduli
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
    log_modulus: CiphertextModulusLog,
) -> NoiseEstimation {
    let mut sum_mask_errors = 0_f64;
    let mut sum_square_mask_errors = 0_f64;

    for mask in masks {
        let error = round_error_float(mask, log_modulus);

        sum_mask_errors += error;
        sum_square_mask_errors += error * error;
    }

    let expectancy = -sum_mask_errors / 2_f64;

    let variance = sum_square_mask_errors / 4_f64;

    NoiseEstimation {
        expectancy,
        variance,
    }
}

pub fn measure_modulus_switch_noise_estimation_for_binary_key<Scalar: UnsignedInteger>(
    r_sigma_factor: RSigmaFactor,
    input_variance: ModularVariance,
    log_modulus: CiphertextModulusLog,
    masks: impl Iterator<Item = Scalar>,
) -> f64 {
    let NoiseEstimation {
        expectancy,
        variance,
    } = measure_modulus_switch_noise_expectancy_variance_for_binary_key(masks, log_modulus);

    let std_dev = (variance + input_variance.value).sqrt();

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
    lwe: &CmLweCiphertext<C1>,
    encryptions_of_zero: &CmLweCiphertextList<C2>,
    r_sigma_factor: RSigmaFactor,
    bound: NoiseEstimationMeasureBound,
    input_variance: Variance,
    log_modulus: CiphertextModulusLog,
) -> CandidateResult
where
    Scalar: UnsignedInteger,
    C1: Container<Element = Scalar>,
    C2: Container<Element = Scalar>,
{
    assert_eq!(
        lwe.lwe_dimension(),
        encryptions_of_zero.lwe_dimension(),
        "input lwe size (={:?}) != encryptions of zero lwe size (={:?})",
        lwe.lwe_dimension(),
        encryptions_of_zero.lwe_dimension(),
    );
    assert_eq!(
        lwe.ciphertext_modulus(),
        encryptions_of_zero.ciphertext_modulus(),
        "input ciphertext_modulus (={:?}) != encryptions of zero ciphertext_modulus (={:?})",
        lwe.ciphertext_modulus(),
        encryptions_of_zero.ciphertext_modulus(),
    );

    assert_ne!(
        encryptions_of_zero.cm_lwe_ciphertext_count().0,
        0,
        "Expected at least one encryption of zero"
    );
    assert_eq!(
        lwe.ciphertext_modulus(),
        CiphertextModulus::new_native(),
        "Non native modulus are not supported, got {}",
        lwe.ciphertext_modulus(),
    );

    let modulus = lwe.ciphertext_modulus().raw_modulus_float();

    let input_variance = input_variance.get_modular_variance(modulus);

    let mask = lwe.get_mask();

    let mask = mask.as_ref();

    let base_measure = measure_modulus_switch_noise_estimation_for_binary_key(
        r_sigma_factor,
        input_variance,
        log_modulus,
        mask.iter().copied(),
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

        let measure = measure_modulus_switch_noise_estimation_for_binary_key(
            r_sigma_factor,
            input_variance,
            log_modulus,
            mask_sum,
        );

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

/// This function can be called before doing a modulus switch.
/// It modifies the input (but not the value it encrypts) in a way that decreases the noise
/// added by the subsequent modulus switch
///
/// Technique is described at <https://eprint.iacr.org/2024/1718.pdf>
pub fn improve_lwe_ciphertext_modulus_switch_noise_for_binary_key<Scalar, C1, C2>(
    lwe: &mut CmLweCiphertext<C1>,
    encryptions_of_zero: &CmLweCiphertextList<C2>,
    r_sigma_factor: RSigmaFactor,
    bound: NoiseEstimationMeasureBound,
    input_variance: Variance,
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
        input_variance,
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

            cm_lwe_ciphertext_add_assign(lwe, &encryption_of_zero);
        }
    }
}

fn cm_lwe_ciphertext_add_assign<Scalar, C1>(
    lwe: &mut CmLweCiphertext<C1>,
    encryption_of_zero: &CmLweCiphertext<&[Scalar]>,
) where
    Scalar: UnsignedInteger,
    C1: ContainerMut<Element = Scalar>,
{
    for (i, j) in izip!(lwe.as_mut().iter_mut(), encryption_of_zero.as_ref().iter()) {
        *i = i.wrapping_add(*j);
    }
}
