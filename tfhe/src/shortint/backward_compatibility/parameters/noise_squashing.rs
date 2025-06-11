use crate::shortint::parameters::noise_squashing::{
    NoiseSquashingCompressionParameters, NoiseSquashingMultiBitParameters, NoiseSquashingParameters,
};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum NoiseSquashingParametersVersions {
    V0(NoiseSquashingParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionParametersVersions {
    V0(NoiseSquashingCompressionParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingMultiBitParametersVersions {
    V0(NoiseSquashingMultiBitParameters),
}
