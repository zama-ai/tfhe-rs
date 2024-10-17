use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::shortint::key_switching_key::{
    CompressedKeySwitchingKeyMaterial, KeySwitchingKeyMaterial,
};
use crate::shortint::{CompressedKeySwitchingKey, KeySwitchingKey};

#[derive(Version)]
pub struct UnsupportedCompressedKeySwitchingKeyMaterialV0;

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyMaterialVersions {
    V0(KeySwitchingKeyMaterial),
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}

impl Upgrade<CompressedKeySwitchingKeyMaterial> for UnsupportedCompressedKeySwitchingKeyMaterialV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<CompressedKeySwitchingKeyMaterial, Self::Error> {
        Err(crate::Error::new(
            "Unable to load CompressedKeySwitchingKeyMaterial, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyMaterialVersions {
    V0(UnsupportedCompressedKeySwitchingKeyMaterialV0),
    V1(CompressedKeySwitchingKeyMaterial),
}

#[derive(Version)]
pub struct UnsupportedCompressedKeySwitchingKeyV0;

impl Upgrade<CompressedKeySwitchingKey> for UnsupportedCompressedKeySwitchingKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<CompressedKeySwitchingKey, Self::Error> {
        Err(crate::Error::new(
            "Unable to load CompressedKeySwitchingKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedKeySwitchingKeyVersions {
    V0(UnsupportedCompressedKeySwitchingKeyV0),
    V1(CompressedKeySwitchingKey),
}
