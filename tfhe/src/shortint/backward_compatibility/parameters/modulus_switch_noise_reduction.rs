use crate::shortint::server_key::ModulusSwitchNoiseReductionParams;
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ModulusSwitchNoiseReductionParamsVersions {
    V0(ModulusSwitchNoiseReductionParams),
}
