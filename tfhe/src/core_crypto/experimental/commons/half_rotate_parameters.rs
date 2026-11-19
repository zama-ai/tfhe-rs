//! Parameter sets for the half-rotate 128-bit PBS, see
//! [`Fourier128HalfRotateLweBootstrapKey`](crate::core_crypto::experimental::entities::Fourier128HalfRotateLweBootstrapKey).

use crate::core_crypto::commons::parameters::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweDimension, PolynomialSize,
};
use crate::core_crypto::experimental::commons::parameters::LweDimensionPart;
use serde::{Deserialize, Serialize};

/// Noise squashing parameters whose blind rotation is split in two sections: the first
/// `input_lwe_dimension_start` input mask elements use the `_start` decomposition, the last
/// `input_lwe_dimension_end` ones the `_end` decomposition.
///
/// The `input_` fields describe the `u64` LWE ciphertexts being squashed, whose LWE dimension is
/// `input_lwe_dimension_start + input_lwe_dimension_end`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct HalfRotateNoiseSquashingParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub input_lwe_dimension_start: LweDimensionPart,
    pub input_lwe_dimension_end: LweDimensionPart,
    pub input_lwe_noise_distribution: DynamicDistribution<u64>,
    pub input_ciphertext_modulus: CiphertextModulus<u64>,
    pub decomp_base_log_start: DecompositionBaseLog,
    pub decomp_level_count_start: DecompositionLevelCount,
    pub decomp_base_log_end: DecompositionBaseLog,
    pub decomp_level_count_end: DecompositionLevelCount,
    pub output_ciphertext_modulus: CiphertextModulus<u128>,
}

impl HalfRotateNoiseSquashingParameters {
    /// LWE dimension of the ciphertexts being squashed.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.input_lwe_dimension_start.0 + self.input_lwe_dimension_end.0)
    }
}

/// Half-rotate variant of the PBS-128 noise squashing parameters for 2_2 TUniform 2^-128, from the
/// optimizer, algorithmic cost ~ 4778
pub const HALF_ROTATE_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    HalfRotateNoiseSquashingParameters = HalfRotateNoiseSquashingParameters {
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    input_lwe_dimension_start: LweDimensionPart(282),
    input_lwe_dimension_end: LweDimensionPart(636),
    input_lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    input_ciphertext_modulus: CiphertextModulus::new_native(),
    decomp_base_log_start: DecompositionBaseLog(32),
    decomp_level_count_start: DecompositionLevelCount(2),
    decomp_base_log_end: DecompositionBaseLog(24),
    decomp_level_count_end: DecompositionLevelCount(3),
    output_ciphertext_modulus: CiphertextModulus::new_native(),
};
