use std::convert::Infallible;

use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::LweKeyswitchKeyOwned;
use crate::shortint::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyDestinationAtomicPattern,
    KeySwitchingKeyMaterial,
};
use crate::shortint::{CompressedKeySwitchingKey, EncryptionKeyChoice, KeySwitchingKey};

#[derive(Version)]
pub struct KeySwitchingKeyMaterialV0 {
    key_switching_key: LweKeyswitchKeyOwned<u64>,
    cast_rshift: i8,
    destination_key: EncryptionKeyChoice,
}

impl Upgrade<KeySwitchingKeyMaterial> for KeySwitchingKeyMaterialV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<KeySwitchingKeyMaterial, Self::Error> {
        Ok(KeySwitchingKeyMaterial {
            key_switching_key: self.key_switching_key,
            cast_rshift: self.cast_rshift,
            destination_key: self.destination_key,
            destination_atomic_pattern: KeySwitchingKeyDestinationAtomicPattern::Standard,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyMaterialVersions {
    V0(KeySwitchingKeyMaterialV0),
    V1(KeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyDestinationAtomicPatternVersions {
    V0(KeySwitchingKeyDestinationAtomicPattern),
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
