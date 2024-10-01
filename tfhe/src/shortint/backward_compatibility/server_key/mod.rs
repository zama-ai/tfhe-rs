use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::shortint::server_key::*;

#[derive(VersionsDispatch)]
pub enum SerializableShortintBootstrappingKeyVersions<C: Container<Element = tfhe_fft::c64>> {
    V0(SerializableShortintBootstrappingKey<C>),
}

impl Deprecable for ServerKey {
    const TYPE_NAME: &'static str = "ServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(Deprecated<ServerKey>),
    V1(ServerKey),
}

impl Deprecable for ShortintCompressedBootstrappingKey {
    const TYPE_NAME: &'static str = "ShortintCompressedBootstrappingKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum ShortintCompressedBootstrappingKeyVersions {
    V0(Deprecated<ShortintCompressedBootstrappingKey>),
    V1(ShortintCompressedBootstrappingKey),
}

impl Deprecable for CompressedServerKey {
    const TYPE_NAME: &'static str = "CompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(Deprecated<CompressedServerKey>),
    V1(Deprecated<CompressedServerKey>),
    V2(CompressedServerKey),
}
