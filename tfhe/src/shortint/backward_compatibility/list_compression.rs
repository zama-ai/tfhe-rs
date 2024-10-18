use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

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

#[derive(Version)]
pub struct UnsupportedCompressedCompressionKeyV0;

impl Upgrade<CompressedCompressionKey> for UnsupportedCompressedCompressionKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<CompressedCompressionKey, Self::Error> {
        Err(crate::Error::new(
            "Unable to load CompressedCompressionKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCompressionKeyVersions {
    V0(UnsupportedCompressedCompressionKeyV0),
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
