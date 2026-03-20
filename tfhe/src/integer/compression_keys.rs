use super::ClientKey;
use crate::conformance::ParameterSetConformant;
use crate::integer::backward_compatibility::list_compression::*;
use crate::named::Named;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressionPrivateKeysVersions)]
pub struct CompressionPrivateKeys {
    pub(crate) key: crate::shortint::list_compression::CompressionPrivateKeys,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
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

impl Named for CompressionPrivateKeys {
    const NAME: &'static str = "integer::CompressionPrivateKeys";
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] =
        &["high_level_api::CompressionPrivateKeys"];
}

impl Named for CompressionKey {
    const NAME: &'static str = "integer::CompressionKey";
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] =
        &["high_level_api::CompressionKey"];
}

impl Named for DecompressionKey {
    const NAME: &'static str = "integer::DecompressionKey";
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] =
        &["high_level_api::DecompressionKey"];
}

impl Named for CompressedCompressionKey {
    const NAME: &'static str = "integer::CompressedCompressionKey";
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] =
        &["high_level_api::CompressedCompressionKey"];
}

impl Named for CompressedDecompressionKey {
    const NAME: &'static str = "integer::CompressedDecompressionKey";
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] =
        &["high_level_api::CompressedDecompressionKey"];
}

impl CompressedCompressionKey {
    pub fn decompress(&self) -> CompressionKey {
        CompressionKey {
            key: self.key.decompress(),
        }
    }

    pub fn into_raw_parts(self) -> crate::shortint::list_compression::CompressedCompressionKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(
        key: crate::shortint::list_compression::CompressedCompressionKey,
    ) -> Self {
        Self { key }
    }
}

impl CompressedDecompressionKey {
    pub fn decompress(&self) -> DecompressionKey {
        DecompressionKey {
            key: self.key.decompress(),
        }
    }

    pub fn into_raw_parts(self) -> crate::shortint::list_compression::CompressedDecompressionKey {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(
        key: crate::shortint::list_compression::CompressedDecompressionKey,
    ) -> Self {
        Self { key }
    }
}

impl CompressionPrivateKeys {
    pub fn into_raw_parts(self) -> crate::shortint::list_compression::CompressionPrivateKeys {
        let Self { key } = self;
        key
    }

    pub fn from_raw_parts(key: crate::shortint::list_compression::CompressionPrivateKeys) -> Self {
        Self { key }
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

use crate::shortint::list_compression::CompressionKeyConformanceParams;

impl ParameterSetConformant for CompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for DecompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for CompressedCompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}

impl ParameterSetConformant for CompressedDecompressionKey {
    type ParameterSet = CompressionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self { key } = self;

        key.is_conformant(parameter_set)
    }
}
