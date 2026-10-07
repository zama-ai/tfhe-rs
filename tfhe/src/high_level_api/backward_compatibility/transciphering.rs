use std::convert::Infallible;

use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::high_level_api::transciphering::{
    AesFheKey, KreyviumFheKey, OneTimePadFheSecretMask, StreamCiphertext,
};
use crate::transciphering::{
    AesFheKey as ShortintAesFheKey, KreyviumFheKey as ShortintKreyviumFheKey,
    OneTimePadFheSecretMask as ShortintOneTimePadFheSecretMask,
};
use crate::Tag;

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}

#[derive(Version)]
pub struct KreyviumFheKeyV0 {
    key: ShortintKreyviumFheKey,
    tag: Tag,
}

impl Upgrade<KreyviumFheKey> for KreyviumFheKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<KreyviumFheKey, Self::Error> {
        Ok(KreyviumFheKey::from_raw_parts(self.key, self.tag))
    }
}

#[derive(VersionsDispatch)]
pub enum KreyviumFheKeyVersions {
    V0(KreyviumFheKeyV0),
    V1(KreyviumFheKey),
}

#[derive(Version)]
pub struct AesFheKeyV0 {
    key: ShortintAesFheKey,
    tag: Tag,
}

impl Upgrade<AesFheKey> for AesFheKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<AesFheKey, Self::Error> {
        Ok(AesFheKey::from_raw_parts(self.key, self.tag))
    }
}

#[derive(VersionsDispatch)]
pub enum AesFheKeyVersions {
    V0(AesFheKeyV0),
    V1(AesFheKey),
}

#[derive(Version)]
pub struct OneTimePadFheSecretMaskV0 {
    key: ShortintOneTimePadFheSecretMask,
    tag: Tag,
}

impl Upgrade<OneTimePadFheSecretMask> for OneTimePadFheSecretMaskV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<OneTimePadFheSecretMask, Self::Error> {
        Ok(OneTimePadFheSecretMask::from_raw_parts(self.key, self.tag))
    }
}

#[derive(VersionsDispatch)]
pub enum OneTimePadFheSecretMaskVersions {
    V0(OneTimePadFheSecretMaskV0),
    V1(OneTimePadFheSecretMask),
}
