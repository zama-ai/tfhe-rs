use crate::high_level_api::backward_compatibility::keys::{
    CompressedReRandomizationKeySwitchingKeyVersions, CompressedReRandomizationKeyVersions,
    ReRandomizationKeySwitchingKeyVersions, ReRandomizationKeyVersions,
};
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use tfhe_versionable::Versionize;

#[derive(Debug, Clone)]
pub(crate) enum ReRandomizationKeySwitchingKeyGenInfo<'a> {
    /// The rerand process uses a CPK that needs a keyswitch, the KSK used is the one already
    /// available to keyswitch to compute params after encryption.
    UseCPKEncryptionKSK,
    /// The rerand process uses a CPK that needs a keyswitch, the KSK used is a dedicated one.
    DedicatedKSK(
        (
            &'a crate::integer::CompactPrivateKey<Vec<u64>>,
            ShortintKeySwitchingParameters,
        ),
    ),
}

#[derive(Debug, Clone)]
pub(crate) enum ReRandomizationKeyGenInfo<'a> {
    LegacyDedicatedCPKWithKeySwitch {
        ksk_gen_info: ReRandomizationKeySwitchingKeyGenInfo<'a>,
    },
    DerivedCPKWithoutKeySwitch {
        derived_compact_private_key: crate::integer::CompactPrivateKey<&'a [u64]>,
    },
}

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(ReRandomizationKeyVersions)]
pub enum ReRandomizationKey {
    /// Previous way of performing re-randomization: the encryption
    /// [`super::public::CompactPublicKey`] is used to generate the required encryptions of zero,
    /// they are then keyswitched to be compatible with the compute keys before being used to
    /// re-randomize the ciphertexts. Prefer [`Self::DerivedCPK`].
    LegacyDedicatedCPK {
        // Legacy code did not have the CPK in the ServerKey
        ksk: ReRandomizationKeySwitchingKey,
    },
    /// Recommended way of performing re-randomization: a specific
    /// [`super::public::CompactPublicKey`] is generated from the compute private keys, meaning
    /// it can be used to generate the required encryptions of zero without needing a keyswitch to
    /// be usable, making it much more efficient than the [`Self::LegacyDedicatedCPK`] mode.
    DerivedCPK {
        cpk: crate::integer::CompactPublicKey,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedReRandomizationKeyVersions)]
pub enum CompressedReRandomizationKey {
    LegacyDedicatedCPK {
        // Legacy code did not have the CPK in the ServerKey
        ksk: CompressedReRandomizationKeySwitchingKey,
    },
    DerivedCPK {
        cpk: crate::integer::CompressedCompactPublicKey,
    },
}

impl CompressedReRandomizationKey {
    pub fn decompress(&self) -> ReRandomizationKey {
        match self {
            Self::LegacyDedicatedCPK { ksk } => ReRandomizationKey::LegacyDedicatedCPK {
                ksk: ksk.decompress(),
            },
            Self::DerivedCPK { cpk } => ReRandomizationKey::DerivedCPK {
                cpk: cpk.decompress(),
            },
        }
    }
}

#[cfg(feature = "gpu")]
pub(crate) enum CudaReRandomizationKeySwitchingKey {
    UseCPKEncryptionKSK,
    DedicatedKSK(crate::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial),
}
