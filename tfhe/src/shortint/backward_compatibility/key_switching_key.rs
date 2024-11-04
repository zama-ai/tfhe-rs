use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::shortint::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::shortint::{CompressedKeySwitchingKey, KeySwitchingKey};

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyMaterialVersions {
    V0(KeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}

impl Deprecable for CompressedKeySwitchingKeyMaterial {
    const TYPE_NAME: &'static str = "CompressedKeySwitchingKeyMaterial";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyMaterialVersions {
    V0(Deprecated<CompressedKeySwitchingKeyMaterial>),
    V1(Deprecated<CompressedKeySwitchingKeyMaterial>),
    V2(CompressedKeySwitchingKeyMaterial),
}

impl Deprecable for CompressedKeySwitchingKey {
    const TYPE_NAME: &'static str = "CompressedKeySwitchingKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyVersions {
    V0(Deprecated<CompressedKeySwitchingKey>),
    V1(Deprecated<CompressedKeySwitchingKey>),
    V2(CompressedKeySwitchingKey),
}
