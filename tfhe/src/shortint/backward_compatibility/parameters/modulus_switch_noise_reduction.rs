use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ModulusSwitchNoiseReductionParamsVersions {
    V0(ModulusSwitchNoiseReductionParams),
}
