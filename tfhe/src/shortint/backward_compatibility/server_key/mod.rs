use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::shortint::server_key::*;

#[derive(VersionsDispatch)]
pub enum SerializableShortintBootstrappingKeyVersions<C: Container<Element = concrete_fft::c64>> {
    V0(SerializableShortintBootstrappingKey<C>),
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(ServerKey),
}

#[derive(VersionsDispatch)]
pub enum ShortintCompressedBootstrappingKeyVersions {
    V0(ShortintCompressedBootstrappingKey),
}

impl Deprecable for CompressedServerKey {
    const TYPE_NAME: &'static str = "CompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.9";
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(Deprecated<CompressedServerKey>),
    V1(CompressedServerKey),
}
