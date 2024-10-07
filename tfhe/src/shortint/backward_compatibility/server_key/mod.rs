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

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(CompressedServerKey),
}
