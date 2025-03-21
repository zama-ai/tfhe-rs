use crate::shortint::backward_compatibility::parameters::list_compression::{
    CompressionParametersVersions, NoiseSquashingCompressionParametersVersions,
};
use crate::shortint::parameters::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweCiphertextCount, PolynomialSize,
};

use std::fmt::Debug;
use tfhe_versionable::Versionize;

use super::CoreCiphertextModulus;

#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressionParametersVersions)]
pub struct CompressionParameters {
    pub br_level: DecompositionLevelCount,
    pub br_base_log: DecompositionBaseLog,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
    pub packing_ks_key_noise_distribution: DynamicDistribution<u64>,
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
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}
