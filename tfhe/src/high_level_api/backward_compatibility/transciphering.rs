use serde::{Deserialize, Serialize};
use tfhe_versionable::VersionsDispatch;

use crate::high_level_api::transciphering::{
    AesFheKeyVersionOwned, KreyviumFheKeyVersionOwned, OneTimePadFheSecretMaskVersionOwned,
    StreamCiphertext,
};

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}

// Manual impl, the device-polymorphic HL keys only serialize their CPU form so
// the version payloads live next to each key type.

#[derive(Serialize, Deserialize)]
pub enum KreyviumFheKeyVersionedOwned {
    V0(KreyviumFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
pub enum AesFheKeyVersionedOwned {
    V0(AesFheKeyVersionOwned),
}

#[derive(Serialize, Deserialize)]
pub enum OneTimePadFheSecretMaskVersionedOwned {
    V0(OneTimePadFheSecretMaskVersionOwned),
}
