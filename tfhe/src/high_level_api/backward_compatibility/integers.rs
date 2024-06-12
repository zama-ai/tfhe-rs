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
pub enum CompactFheIntVersions<Id: FheIntId> {
    V0(CompactFheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheIntVersions<Id: FheIntId> {
    V0(CompressedFheInt<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheIntListVersions<Id: FheIntId> {
    V0(CompactFheIntList<Id>),
}

#[derive(VersionsDispatch)]
pub enum FheUintVersions<Id: FheUintId> {
    V0(FheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheUintVersions<Id: FheUintId> {
    V0(CompactFheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheUintVersions<Id: FheUintId> {
    V0(CompressedFheUint<Id>),
}

#[derive(VersionsDispatch)]
pub enum CompactFheUintListVersions<Id: FheUintId> {
    V0(CompactFheUintList<Id>),
}

#[derive(VersionsDispatch)]
pub enum FheInt2IdVersions {
    V0(FheInt2Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt4IdVersions {
    V0(FheInt4Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt6IdVersions {
    V0(FheInt6Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt8IdVersions {
    V0(FheInt8Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt10IdVersions {
    V0(FheInt10Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt12IdVersions {
    V0(FheInt12Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt14IdVersions {
    V0(FheInt14Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt16IdVersions {
    V0(FheInt16Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt32IdVersions {
    V0(FheInt32Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt64IdVersions {
    V0(FheInt64Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt128IdVersions {
    V0(FheInt128Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt160IdVersions {
    V0(FheInt160Id),
}

#[derive(VersionsDispatch)]
pub enum FheInt256IdVersions {
    V0(FheInt256Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint2IdVersions {
    V0(FheUint2Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint4IdVersions {
    V0(FheUint4Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint6IdVersions {
    V0(FheUint6Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint8IdVersions {
    V0(FheUint8Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint10IdVersions {
    V0(FheUint10Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint12IdVersions {
    V0(FheUint12Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint14IdVersions {
    V0(FheUint14Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint16IdVersions {
    V0(FheUint16Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint32IdVersions {
    V0(FheUint32Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint64IdVersions {
    V0(FheUint64Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint128IdVersions {
    V0(FheUint128Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint160IdVersions {
    V0(FheUint160Id),
}

#[derive(VersionsDispatch)]
pub enum FheUint256IdVersions {
    V0(FheUint256Id),
}
