use crate::shortint::backward_compatibility::parameters::noise_squashing::*;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, MessageModulus,
    ModulusSwitchNoiseReductionParams, PolynomialSize,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingParametersVersions)]
pub struct NoiseSquashingParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}

#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NoiseSquashingCompressionParametersVersions)]
pub struct NoiseSquashingCompressionParameters {
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub packing_ks_key_noise_distribution: DynamicDistribution<u128>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}
