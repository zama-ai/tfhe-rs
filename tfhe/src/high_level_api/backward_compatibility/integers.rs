use tfhe_versionable::VersionsDispatch;

use crate::high_level_api::integers::*;
use serde::{Deserialize, Serialize};

// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum SignedRadixCiphertextVersionedOwned {
    V0(SignedRadixCiphertextVersionOwned),
}

#[derive(Serialize, Deserialize)]
pub(crate) enum UnsignedRadixCiphertextVersionedOwned {
    V0(UnsignedRadixCiphertextVersionOwned),
}

#[derive(VersionsDispatch)]
pub enum CompressedSignedRadixCiphertextVersions {
    V0(CompressedSignedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedRadixCiphertextVersions {
    V0(CompressedRadixCiphertext),
}

#[derive(VersionsDispatch)]
pub enum FheIntVersions<Id: FheIntId> {
    V0(FheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheIntVersions<Id: FheIntId> {
    V0(CompressedFheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum FheUintVersions<Id: FheUintId> {
    V0(FheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheUintVersions<Id: FheUintId> {
    V0(CompressedFheUint<Id>),
}
