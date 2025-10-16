use crate::shortint::backward_compatibility::parameters::list_compression::{
    ClassicCompressionParametersVersions, CompressionParametersVersions,
    MultiBitCompressionParametersVersions,
};
use crate::shortint::parameters::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweBskGroupingFactor, LweCiphertextCount, PolynomialSize,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressionParametersVersions)]
pub enum CompressionParameters {
    Classic(ClassicCompressionParameters),
    MultiBit(MultiBitCompressionParameters),
}

impl CompressionParameters {
    pub fn br_level(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.br_level
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.br_level
            }
        }
    }
    pub fn br_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.br_base_log
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.br_base_log
            }
        }
    }
    pub fn packing_ks_level(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.packing_ks_level
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.packing_ks_level
            }
        }
    }
    pub fn packing_ks_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.packing_ks_base_log
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.packing_ks_base_log
            }
        }
    }
    pub fn packing_ks_polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.packing_ks_polynomial_size
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.packing_ks_polynomial_size
            }
        }
    }
    pub fn packing_ks_glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.packing_ks_glwe_dimension
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.packing_ks_glwe_dimension
            }
        }
    }
    pub fn lwe_per_glwe(&self) -> LweCiphertextCount {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.lwe_per_glwe
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.lwe_per_glwe
            }
        }
    }
    pub fn storage_log_modulus(&self) -> CiphertextModulusLog {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.storage_log_modulus
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.storage_log_modulus
            }
        }
    }
    pub fn packing_ks_key_noise_distribution(&self) -> DynamicDistribution<u64> {
        match self {
            Self::Classic(classic_compression_parameters) => {
                classic_compression_parameters.packing_ks_key_noise_distribution
            }
            Self::MultiBit(multi_bit_compression_parameters) => {
                multi_bit_compression_parameters.packing_ks_key_noise_distribution
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ClassicCompressionParametersVersions)]
pub struct ClassicCompressionParameters {
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

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(MultiBitCompressionParametersVersions)]
pub struct MultiBitCompressionParameters {
    pub br_level: DecompositionLevelCount,
    pub br_base_log: DecompositionBaseLog,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub storage_log_modulus: CiphertextModulusLog,
    pub packing_ks_key_noise_distribution: DynamicDistribution<u64>,
    pub decompression_grouping_factor: LweBskGroupingFactor,
}
