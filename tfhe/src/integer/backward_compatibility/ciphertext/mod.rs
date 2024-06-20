use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::integer::ciphertext::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CompactCiphertextList,
    CompressedModulusSwitchedRadixCiphertext, CompressedModulusSwitchedRadixCiphertextGeneric,
    CompressedModulusSwitchedSignedRadixCiphertext, DataKind,
};
use crate::integer::BooleanBlock;

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
    fn upgrade(self) -> Result<CompactCiphertextList, String> {
        println!("WARNING: Upgrading from old CompactCiphertextList with no sign information. Trying to guess type or defaulting to unsigned");
        let radix_count =
            self.ct_list.ct_list.lwe_ciphertext_count().0 / self.num_blocks_per_integer;
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
