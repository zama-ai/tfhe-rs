use crate::shortint::server_key::{
    CompressedModulusSwitchNoiseReductionKey, ModulusSwitchNoiseReductionKey,
};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum ModulusSwitchNoiseReductionKeyVersions {
    V0(ModulusSwitchNoiseReductionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchNoiseReductionKeyVersions {
    V0(CompressedModulusSwitchNoiseReductionKey),
}
