use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::shortint::backward_compatibility::parameters::noise_squashing::*;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, MessageModulus, ModulusSwitchType,
    PolynomialSize,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingParametersVersions)]
pub enum NoiseSquashingParameters {
    Classic(NoiseSquashingClassicParameters),
    MultiBit(NoiseSquashingMultiBitParameters),
}

impl NoiseSquashingParameters {
    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.polynomial_size
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.polynomial_size
            }
        }
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.glwe_dimension
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.glwe_dimension
            }
        }
    }

    pub fn message_modulus(&self) -> MessageModulus {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.message_modulus
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.message_modulus
            }
        }
    }
    pub fn carry_modulus(&self) -> CarryModulus {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.carry_modulus
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.carry_modulus
            }
        }
    }
    pub fn decomp_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.decomp_base_log
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.decomp_base_log
            }
        }
    }
    pub fn decomp_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.decomp_level_count
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.decomp_level_count
            }
        }
    }
    pub fn glwe_noise_distribution(&self) -> DynamicDistribution<u128> {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.glwe_noise_distribution
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.glwe_noise_distribution
            }
        }
    }
    pub fn ciphertext_modulus(&self) -> CoreCiphertextModulus<u128> {
        match self {
            Self::Classic(noise_squashing_classic_parameters) => {
                noise_squashing_classic_parameters.ciphertext_modulus
            }
            Self::MultiBit(noise_squashing_multi_bit_parameters) => {
                noise_squashing_multi_bit_parameters.ciphertext_modulus
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingClassicParametersVersions)]
pub struct NoiseSquashingClassicParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(NoiseSquashingMultiBitParametersVersions)]
pub struct NoiseSquashingMultiBitParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub grouping_factor: LweBskGroupingFactor,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
    pub deterministic_execution: bool,
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MetaNoiseSquashingParameters {
    /// Parameters to do the actual noise squashing
    pub parameters: NoiseSquashingParameters,
    /// Parameters for compression of noise squashed ciphertexts aka
    /// CompressedSquashedNoiseCiphertextList
    pub compression_parameters: Option<NoiseSquashingCompressionParameters>,
}
