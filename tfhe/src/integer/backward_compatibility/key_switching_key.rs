use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

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

#[derive(Version)]
pub struct UnsupportedCompressedKeySwitchingKeyMaterialV0;

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
