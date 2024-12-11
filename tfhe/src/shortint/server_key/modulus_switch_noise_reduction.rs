use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::NotVersioned;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: usize,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
}
