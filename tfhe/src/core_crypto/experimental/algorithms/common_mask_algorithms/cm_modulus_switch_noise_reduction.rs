use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::{NoiseEstimationMeasureBound, RSigmaFactor};
use crate::core_crypto::commons::traits::{Container, ContainerMut, UnsignedInteger};
use crate::core_crypto::experimental::entities::{CmLweCiphertext, CmLweCiphertextList};
use crate::core_crypto::experimental::prelude::cm_lwe_ciphertext_add_assign;
use crate::core_crypto::prelude::modulus_switch_noise_reduction::{
    measure_modulus_switch_noise_estimation_for_binary_key, Candidate, CandidateResult,
};
use crate::core_crypto::prelude::{
    CiphertextModulus, CiphertextModulusLog, ContiguousEntityContainer, DispersionParameter,
};
use itertools::Itertools;

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
        Scalar::ZERO,
    );

    let mut best_candidate = Candidate::NoAddition;
    let mut best_measure = base_measure;

    if base_measure <= bound.0 {
        return CandidateResult::SatisfyingBound(best_candidate);
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
            Scalar::ZERO,
        );

        if measure < best_measure {
            best_measure = measure;
            best_candidate = Candidate::AddEncryptionOfZero { index };
        }

        if measure <= bound.0 {
            return CandidateResult::SatisfyingBound(best_candidate);
        }
    }

    CandidateResult::BestNotSatisfyingBound(best_candidate)
}

pub fn improve_lwe_ciphertext_modulus_switch_noise_for_binary_key_cm<Scalar, C1, C2>(
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
        matches!(candidate, CandidateResult::SatisfyingBound(_)),
        "MS noise reduction bound not reached for any candidate"
    );

    let candidate = match candidate {
        CandidateResult::SatisfyingBound(candidate) => candidate,
        CandidateResult::BestNotSatisfyingBound(candidate) => candidate,
    };

    match candidate {
        Candidate::NoAddition => {}
        Candidate::AddEncryptionOfZero { index } => {
            let encryption_of_zero = encryptions_of_zero.get(index);

            cm_lwe_ciphertext_add_assign(lwe, &encryption_of_zero);
        }
    }
}
