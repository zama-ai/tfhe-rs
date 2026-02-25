use tfhe_versionable::VersionsDispatch;

use crate::generators::aes_ctr::{AesCtrParams, AesIndex, ByteIndex, TableIndex};

#[derive(VersionsDispatch)]
pub enum AesIndexVersions {
    V0(AesIndex),
}

#[derive(VersionsDispatch)]
pub enum ByteIndexVersions {
    V0(ByteIndex),
}

#[derive(VersionsDispatch)]
pub enum TableIndexVersions {
    V0(TableIndex),
}

#[derive(VersionsDispatch)]
pub enum AesCtrParamsVersions {
    V0(AesCtrParams),
}
