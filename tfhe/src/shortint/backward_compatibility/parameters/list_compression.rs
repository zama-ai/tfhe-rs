use std::convert::Infallible;

use super::parameters::list_compression::CompressionParameters;
use crate::core_crypto::prelude::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweCiphertextCount, PolynomialSize,
};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
pub struct CompressionParametersV0 {
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

impl Upgrade<CompressionParameters> for CompressionParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressionParameters, Self::Error> {
        let Self {
            br_level,
            br_base_log,
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            lwe_per_glwe,
            storage_log_modulus,
            packing_ks_key_noise_distribution,
        } = self;

        Ok(CompressionParameters {
            br_level,
            br_base_log,
            packing_ks_level,
            packing_ks_base_log,
            packing_ks_polynomial_size,
            packing_ks_glwe_dimension,
            decompression_grouping_factor: None,
            lwe_per_glwe,
            storage_log_modulus,
            packing_ks_key_noise_distribution,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressionParametersVersions {
    V0(CompressionParametersV0),
    V1(CompressionParameters),
}
