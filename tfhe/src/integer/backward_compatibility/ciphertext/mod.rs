use crate::integer::ciphertext::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CompactCiphertextList,
    CompressedCiphertextList, CompressedModulusSwitchedRadixCiphertext,
    CompressedModulusSwitchedRadixCiphertextGeneric,
    CompressedModulusSwitchedSignedRadixCiphertext, DataKind, SquashedNoiseBooleanBlock,
    SquashedNoiseRadixCiphertext, SquashedNoiseSignedRadixCiphertext,
};
use crate::integer::server_key::CompressedKVStore;
use crate::integer::BooleanBlock;
#[cfg(feature = "zk-pok")]
use crate::integer::ProvenCompactCiphertextList;
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;
use std::convert::Infallible;
use std::num::NonZero;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum BaseRadixCiphertextVersions<Block> {
    V0(BaseRadixCiphertext<Block>),
}

#[derive(VersionsDispatch)]
pub enum BaseSignedRadixCiphertextVersions<Block> {
    V0(BaseSignedRadixCiphertext<Block>),
}

#[derive(VersionsDispatch)]
pub enum BaseCrtCiphertextVersions<Block> {
    V0(BaseCrtCiphertext<Block>),
}

#[derive(Version)]
pub struct CompactCiphertextListV0 {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    pub(crate) num_blocks_per_integer: usize,
}

impl Upgrade<CompactCiphertextList> for CompactCiphertextListV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactCiphertextList, Self::Error> {
        let radix_count =
            self.ct_list.ct_list.lwe_ciphertext_count().0 / self.num_blocks_per_integer;
        // Since we can't guess the type of data here, we set them by default as unsigned integer.
        // Since it this data comes from 0.6, if it is included in a homogeneous compact list it
        // will be converted to the right type at expand time.

        let info = NonZero::new(self.num_blocks_per_integer)
            .map(|n| vec![DataKind::Unsigned(n); radix_count])
            .unwrap_or_default();

        Ok(CompactCiphertextList::from_raw_parts(self.ct_list, info))
    }
}

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextListV0),
    V1(CompactCiphertextList),
}

#[cfg(feature = "zk-pok")]
#[derive(VersionsDispatch)]
pub enum ProvenCompactCiphertextListVersions {
    V0(ProvenCompactCiphertextList),
}

#[derive(Version)]
pub enum DataKindV0 {
    /// The held value is a number of radix blocks.
    Unsigned(usize),
    /// The held value is a number of radix blocks.
    Signed(usize),
    Boolean,
    String {
        n_chars: u32,
        padded: bool,
    },
}

#[derive(VersionsDispatch)]
pub enum DataKindVersions {
    V0(DataKindV0),
    V1(DataKind),
}

impl Upgrade<DataKind> for DataKindV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<DataKind, Self::Error> {
        match self {
            Self::Unsigned(n) => NonZero::new(n)
                .ok_or_else(|| crate::error!("DataKind::Unsigned requires non-zero block count"))
                .map(DataKind::Unsigned),
            Self::Signed(n) => NonZero::new(n)
                .ok_or_else(|| crate::error!("DataKind::Signed requires non-zero block count"))
                .map(DataKind::Signed),
            Self::Boolean => Ok(DataKind::Boolean),
            Self::String { n_chars, padded } => Ok(DataKind::String { n_chars, padded }),
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedSignedRadixCiphertextVersions {
    V0(CompressedModulusSwitchedSignedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchedRadixCiphertextVersions {
    V0(CompressedModulusSwitchedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub(crate) enum CompressedModulusSwitchedRadixCiphertextGenericVersions {
    #[allow(dead_code)]
    V0(CompressedModulusSwitchedRadixCiphertextGeneric),
}

#[derive(VersionsDispatch)]
pub enum BooleanBlockVersions {
    V0(BooleanBlock),
}

// Before 0.7 these types were just aliases, so they were not versioned. Strictly speakind, this is
// a data breaking change since they cannot be loaded as-is
pub type CompressedModulusSwitchedSignedRadixCiphertextTFHE06 =
    BaseSignedRadixCiphertext<CompressedModulusSwitchedCiphertext>;

pub type CompressedModulusSwitchedRadixCiphertextTFHE06 =
    BaseRadixCiphertext<CompressedModulusSwitchedCiphertext>;

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseRadixCiphertextVersions {
    V0(SquashedNoiseRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseSignedRadixCiphertextVersions {
    V0(SquashedNoiseSignedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum SquashedNoiseBooleanBlockVersions {
    V0(SquashedNoiseBooleanBlock),
}

#[derive(VersionsDispatch)]
pub enum CompressedKVStoreVersions<K, V> {
    V0(CompressedKVStore<K, V>),
}
