use crate::core_crypto::commons::parameters::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor,
};
use crate::shortint::backward_compatibility::parameters::modulus_switch_noise_reduction::ModulusSwitchNoiseReductionParamsVersions;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchNoiseReductionParamsVersions)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: LweCiphertextCount,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
}
