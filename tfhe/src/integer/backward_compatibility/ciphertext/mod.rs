use tfhe_versionable::VersionsDispatch;

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

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextList),
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
