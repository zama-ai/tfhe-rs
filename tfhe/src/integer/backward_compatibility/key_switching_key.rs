use tfhe_versionable::VersionsDispatch;

use crate::integer::key_switching_key::{
    CompressedKeySwitchingKey, CompressedKeySwitchingKeyMaterial, KeySwitchingKey,
    KeySwitchingKeyMaterial,
};

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyMaterialVersions {
    V0(KeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyMaterialVersions {
    V0(CompressedKeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyVersions {
    V0(CompressedKeySwitchingKey),
}
