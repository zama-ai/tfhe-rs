use crate::core_crypto::commons::parameters::{
    LweCiphertextCount, NoiseEstimationMeasureBound, RSigmaFactor,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::NotVersioned;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: LweCiphertextCount,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
}
