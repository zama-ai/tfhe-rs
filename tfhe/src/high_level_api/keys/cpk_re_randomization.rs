use crate::high_level_api::backward_compatibility::keys::{
    CompressedReRandomizationKeySwitchingKeyVersions, ReRandomizationKeySwitchingKeyVersions,
};
use tfhe_versionable::Versionize;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ReRandomizationKeySwitchingKeyVersions)]
pub enum ReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::key_switching_key::KeySwitchingKeyMaterial),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedReRandomizationKeySwitchingKeyVersions)]
pub enum CompressedReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial),
}

impl CompressedReRandomizationKeySwitchingKey {
    pub fn decompress(&self) -> ReRandomizationKeySwitchingKey {
        match self {
            Self::UseCPKEncryptionKSK => ReRandomizationKeySwitchingKey::UseCPKEncryptionKSK,
            Self::DedicatedKSK(compressed_key_switching_key_material) => {
                ReRandomizationKeySwitchingKey::DedicatedKSK(
                    compressed_key_switching_key_material.decompress(),
                )
            }
        }
    }
}
