use crate::shortint::parameters::noise_squashing::{
    NoiseSquashingMultiBitParameters, NoiseSquashingParameters,
};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum NoiseSquashingParametersVersions {
    V0(NoiseSquashingParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingMultiBitParametersVersions {
    V0(NoiseSquashingMultiBitParameters),
}
