use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};
use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum CompressionKeyVersions {
    V0(CompressionKey),
}

#[derive(VersionsDispatch)]
pub enum DecompressionKeyVersions {
    V0(DecompressionKey),
}

impl Deprecable for CompressedCompressionKey {
    const TYPE_NAME: &'static str = "CompressedCompressionKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.9";
}

#[derive(VersionsDispatch)]
pub enum CompressedCompressionKeyVersions {
    V0(Deprecated<CompressedCompressionKey>),
    V1(CompressedCompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedDecompressionKeyVersions {
    V0(CompressedDecompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressionPrivateKeysVersions {
    V0(CompressionPrivateKeys),
}
