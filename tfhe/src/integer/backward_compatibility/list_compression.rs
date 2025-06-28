use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, CompressedSquashedNoiseCiphertextList,
    NoiseSquashingCompressionKey, NoiseSquashingCompressionPrivateKey,
};
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
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedCompressionKeyVersions {
    V0(Deprecated<CompressedCompressionKey>),
    V1(Deprecated<CompressedCompressionKey>),
    V2(CompressedCompressionKey),
}

impl Deprecable for CompressedDecompressionKey {
    const TYPE_NAME: &'static str = "CompressedDecompressionKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedDecompressionKeyVersions {
    V0(Deprecated<CompressedDecompressionKey>),
    V1(CompressedDecompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressionPrivateKeysVersions {
    V0(CompressionPrivateKeys),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionKeyVersions {
    V0(NoiseSquashingCompressionKey),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionPrivateKeyVersions {
    V0(NoiseSquashingCompressionPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingCompressionKeyVersions {
    V0(CompressedNoiseSquashingCompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedSquashedNoiseCiphertextListVersions {
    V0(CompressedSquashedNoiseCiphertextList),
}
