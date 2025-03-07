use crate::shortint::backward_compatibility::parameters::noise_squashing::NoiseSquashingParametersVersions;
use crate::shortint::parameters::{
    CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, ModulusSwitchNoiseReductionParams, PolynomialSize,
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
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}
