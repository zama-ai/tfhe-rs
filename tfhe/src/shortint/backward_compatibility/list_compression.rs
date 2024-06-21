use tfhe_versionable::VersionsDispatch;

use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};

#[derive(VersionsDispatch)]
pub enum CompressionKeyVersions {
    V0(CompressionKey),
}

#[derive(VersionsDispatch)]
pub enum DecompressionKeyVersions {
    V0(DecompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedCompressionKeyVersions {
    V0(CompressedCompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedDecompressionKeyVersions {
    V0(CompressedDecompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressionPrivateKeysVersions {
    V0(CompressionPrivateKeys),
}
