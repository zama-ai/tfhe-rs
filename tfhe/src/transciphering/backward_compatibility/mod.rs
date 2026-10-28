use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::shortint::Ciphertext;
use crate::transciphering::{
    AesIv, AesPlainKey, CompressedTranscipheringServerKey, KeyStreamLayout, KreyviumIV,
    KreyviumPlainKey, OneTimePadFheSecretMask, OneTimePadPlainSecretMask, SerializableAesFheKey,
    SerializableKreyviumFheKey, StreamCipherKind, StreamCiphertext, TranscipheringPrivateKey,
    TranscipheringServerKey,
};

#[derive(VersionsDispatch)]
pub enum StreamCipherKindVersions {
    V0(StreamCipherKind),
}

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}

#[derive(VersionsDispatch)]
pub enum SerializableKreyviumFheKeyVersions {
    V0(SerializableKreyviumFheKey),
}

#[derive(VersionsDispatch)]
pub enum KreyviumIVVersions {
    V0(KreyviumIV),
}

#[derive(VersionsDispatch)]
pub enum KreyviumPlainKeyVersions {
    V0(KreyviumPlainKey),
}

#[derive(VersionsDispatch)]
pub enum SerializableAesFheKeyVersions {
    V0(SerializableAesFheKey),
}

#[derive(VersionsDispatch)]
pub enum AesIvVersions {
    V0(AesIv),
}

#[derive(VersionsDispatch)]
pub enum AesPlainKeyVersions {
    V0(AesPlainKey),
}

#[derive(Version)]
pub struct OneTimePadFheSecretMaskV0 {
    secret_mask: Vec<Ciphertext>,
}

impl Upgrade<OneTimePadFheSecretMask> for OneTimePadFheSecretMaskV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<OneTimePadFheSecretMask, Self::Error> {
        let Self { secret_mask } = self;

        OneTimePadFheSecretMask::try_new(
            secret_mask,
            // Previous version without explicit layout stored only 1 bit per ct
            KeyStreamLayout::single_bit(),
        )
    }
}

#[derive(VersionsDispatch)]
pub enum OneTimePadFheSecretMaskVersions {
    V0(OneTimePadFheSecretMaskV0),
    V1(OneTimePadFheSecretMask),
}

#[derive(VersionsDispatch)]
pub enum OneTimePadPlainSecretMaskVersions {
    V0(OneTimePadPlainSecretMask),
}

#[derive(VersionsDispatch)]
pub enum TranscipheringPrivateKeyVersions {
    V0(TranscipheringPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum TranscipheringServerKeyVersions {
    V0(TranscipheringServerKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedTranscipheringServerKeyVersions {
    V0(CompressedTranscipheringServerKey),
}

#[derive(VersionsDispatch)]
pub enum KeyStreamLayoutVersions {
    V0(KeyStreamLayout),
}
