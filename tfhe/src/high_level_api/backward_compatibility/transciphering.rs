use serde::{Deserialize, Serialize};
use tfhe_versionable::{VersionizeOwned, VersionsDispatch};

use crate::high_level_api::transciphering::StreamCiphertext;
use crate::transciphering::{
    AesFheKey as ShortintAesFheKey, KreyviumFheKey as ShortintKreyviumFheKey,
    OneTimePadFheSecretMask as ShortintOneTimePadFheSecretMask,
};

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}

// The device-polymorphic HL keys only serialize their CPU form, so we version
// the underlying shortint key.

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct KreyviumFheKeyVersionOwned(
    pub(crate) <ShortintKreyviumFheKey as VersionizeOwned>::VersionedOwned,
);

#[derive(Serialize, Deserialize)]
pub enum KreyviumFheKeyVersionedOwned {
    V0(KreyviumFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct AesFheKeyVersionOwned(pub(crate) <ShortintAesFheKey as VersionizeOwned>::VersionedOwned);

#[derive(Serialize, Deserialize)]
pub enum AesFheKeyVersionedOwned {
    V0(AesFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct OneTimePadFheSecretMaskVersionOwned(
    pub(crate) <ShortintOneTimePadFheSecretMask as VersionizeOwned>::VersionedOwned,
);

#[derive(Serialize, Deserialize)]
pub enum OneTimePadFheSecretMaskVersionedOwned {
    V0(OneTimePadFheSecretMaskVersionOwned),
}
