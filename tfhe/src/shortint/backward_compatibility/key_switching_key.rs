use tfhe_versionable::VersionsDispatch;

use crate::shortint::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyMaterialVersions {
    V0(KeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyMaterialVersions {
    V0(CompressedKeySwitchingKeyMaterial),
}
