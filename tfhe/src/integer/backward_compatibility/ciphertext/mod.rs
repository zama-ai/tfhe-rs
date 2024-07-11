use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::integer::ciphertext::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CompactCiphertextList,
    CompressedCiphertextList, CompressedModulusSwitchedRadixCiphertext,
    CompressedModulusSwitchedRadixCiphertextGeneric,
    CompressedModulusSwitchedSignedRadixCiphertext, DataKind,
};
use crate::integer::BooleanBlock;
use crate::shortint::ciphertext::CompressedModulusSwitchedCiphertext;

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
        let info = vec![DataKind::Unsigned(self.num_blocks_per_integer); radix_count];

        Ok(CompactCiphertextList::from_raw_parts(self.ct_list, info))
    }
}

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextListV0),
    V1(CompactCiphertextList),
}

#[derive(VersionsDispatch)]
pub enum DataKindVersions {
    V0(DataKind),
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
#[allow(dead_code)]
pub(crate) enum CompressedModulusSwitchedRadixCiphertextGenericVersions {
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
