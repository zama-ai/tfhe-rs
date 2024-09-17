use super::ClientKey;
use crate::integer::backward_compatibility::list_compression::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressionPrivateKeysVersions)]
pub struct CompressionPrivateKeys {
    pub(crate) key: crate::shortint::list_compression::CompressionPrivateKeys,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressionKeyVersions)]
pub struct CompressionKey {
    pub(crate) key: crate::shortint::list_compression::CompressionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(DecompressionKeyVersions)]
pub struct DecompressionKey {
    pub(crate) key: crate::shortint::list_compression::DecompressionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCompressionKeyVersions)]
pub struct CompressedCompressionKey {
    pub(crate) key: crate::shortint::list_compression::CompressedCompressionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedDecompressionKeyVersions)]
pub struct CompressedDecompressionKey {
    pub(crate) key: crate::shortint::list_compression::CompressedDecompressionKey,
}

impl CompressedCompressionKey {
    pub fn decompress(&self) -> CompressionKey {
        CompressionKey {
            key: self.key.decompress(),
        }
    }
}

impl CompressedDecompressionKey {
    pub fn decompress(&self) -> DecompressionKey {
        DecompressionKey {
            key: self.key.decompress(),
        }
    }
}

impl CompressionKey {
    pub fn into_raw_parts(self) -> crate::shortint::list_compression::CompressionKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(key: crate::shortint::list_compression::CompressionKey) -> Self {
        Self { key }
    }
}

impl DecompressionKey {
    pub fn into_raw_parts(self) -> crate::shortint::list_compression::DecompressionKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(key: crate::shortint::list_compression::DecompressionKey) -> Self {
        Self { key }
    }
}

impl ClientKey {
    pub fn new_compressed_compression_decompression_keys(
        &self,
        private_compression_key: &CompressionPrivateKeys,
    ) -> (CompressedCompressionKey, CompressedDecompressionKey) {
        let (comp_key, decomp_key) = self
            .key
            .new_compressed_compression_decompression_keys(&private_compression_key.key);

        (
            CompressedCompressionKey { key: comp_key },
            CompressedDecompressionKey { key: decomp_key },
        )
    }
}
