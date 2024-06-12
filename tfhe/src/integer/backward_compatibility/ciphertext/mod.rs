use tfhe_versionable::VersionsDispatch;

use crate::integer::ciphertext::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CompactCiphertextList,
};

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
