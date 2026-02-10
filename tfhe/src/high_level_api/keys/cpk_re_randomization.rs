use crate::high_level_api::backward_compatibility::keys::{
    CompressedReRandomizationKeySwitchingKeyVersions, ReRandomizationKeySwitchingKeyVersions,
};
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use tfhe_versionable::Versionize;

#[derive(Debug, Clone)]
pub(crate) enum ReRandomizationKeyGenerationInfo<'a> {
    UseCPKEncryptionKSK,
    DedicatedKSK(
        (
            &'a crate::integer::CompactPrivateKey<Vec<u64>>,
            ShortintKeySwitchingParameters,
        ),
    ),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ReRandomizationKeySwitchingKeyVersions)]
pub enum ReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::key_switching_key::KeySwitchingKeyMaterial),
    NoKeySwitch,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedReRandomizationKeySwitchingKeyVersions)]
pub enum CompressedReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial),
    NoKeySwitch,
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
            Self::NoKeySwitch => ReRandomizationKeySwitchingKey::NoKeySwitch,
        }
    }
}

#[cfg(feature = "gpu")]
pub(crate) enum CudaReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial),
}
