use serde::{Deserialize, Serialize};
use tfhe_versionable::{VersionizeOwned, VersionsDispatch};

use crate::high_level_api::transciphering::StreamCiphertext;
use crate::transciphering::{
    AesFheKey as ShortintAesFheKey, KreyviumFheKey as ShortintKreyviumFheKey,
    OneTimePadFheSecretMask as ShortintOneTimePadFheSecretMask,
};
use crate::Tag;

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}

// The device-polymorphic HL keys only serialize their CPU form, so we version
// the underlying cpu key.

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct KreyviumFheKeyVersionOwned {
    pub(crate) key: <ShortintKreyviumFheKey as VersionizeOwned>::VersionedOwned,
    pub(crate) tag: <Tag as VersionizeOwned>::VersionedOwned,
}

#[derive(Serialize, Deserialize)]
pub enum KreyviumFheKeyVersionedOwned {
    V0(KreyviumFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct AesFheKeyVersionOwned {
    pub(crate) key: <ShortintAesFheKey as VersionizeOwned>::VersionedOwned,
    pub(crate) tag: <Tag as VersionizeOwned>::VersionedOwned,
}

#[derive(Serialize, Deserialize)]
pub enum AesFheKeyVersionedOwned {
    V0(AesFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct OneTimePadFheSecretMaskVersionOwned {
    pub(crate) key: <ShortintOneTimePadFheSecretMask as VersionizeOwned>::VersionedOwned,
    pub(crate) tag: <Tag as VersionizeOwned>::VersionedOwned,
}

#[derive(Serialize, Deserialize)]
pub enum OneTimePadFheSecretMaskVersionedOwned {
    V0(OneTimePadFheSecretMaskVersionOwned),
}
