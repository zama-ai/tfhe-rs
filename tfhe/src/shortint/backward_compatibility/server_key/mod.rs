use serde::{Deserialize, Serialize};
use tfhe_versionable::{UnversionizeError, VersionsDispatch};

use crate::core_crypto::prelude::{Container, IntoContainerOwned};
use crate::shortint::server_key::*;

#[derive(Serialize)]
pub enum SerializableShortintBootstrappingKeyVersioned<'vers> {
    V0(SerializableShortintBootstrappingKeyVersion<'vers>),
}

impl<'vers, C: Container<Element = concrete_fft::c64>>
    From<&'vers SerializableShortintBootstrappingKey<C>>
    for SerializableShortintBootstrappingKeyVersioned<'vers>
{
    fn from(value: &'vers SerializableShortintBootstrappingKey<C>) -> Self {
        Self::V0(value.into())
    }
}

#[derive(Serialize, Deserialize)]
pub enum SerializableShortintBootstrappingKeyVersionedOwned {
    V0(SerializableShortintBootstrappingKeyVersionOwned),
}

impl<C: Container<Element = concrete_fft::c64>> From<&SerializableShortintBootstrappingKey<C>>
    for SerializableShortintBootstrappingKeyVersionedOwned
{
    fn from(value: &SerializableShortintBootstrappingKey<C>) -> Self {
        Self::V0(value.into())
    }
}

impl<C: IntoContainerOwned<Element = concrete_fft::c64>>
    TryFrom<SerializableShortintBootstrappingKeyVersionedOwned>
    for SerializableShortintBootstrappingKey<C>
{
    type Error = UnversionizeError;

    fn try_from(
        value: SerializableShortintBootstrappingKeyVersionedOwned,
    ) -> Result<Self, Self::Error> {
        match value {
            SerializableShortintBootstrappingKeyVersionedOwned::V0(v0) => v0.try_into(),
        }
    }
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
