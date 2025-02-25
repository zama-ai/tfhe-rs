use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum NoiseSquashingParametersVersions {
    V0(NoiseSquashingParameters),
}
