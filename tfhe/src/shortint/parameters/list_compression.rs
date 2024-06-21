use tfhe_versionable::Versionize;

use crate::core_crypto::prelude::{CiphertextModulusLog, LweCiphertextCount};
use crate::shortint::backward_compatibility::parameters::list_compression::CompressionParametersVersions;
use crate::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    PolynomialSize,
};
use std::fmt::Debug;

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
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

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(25),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(8),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(5),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(11),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(36),
    };
