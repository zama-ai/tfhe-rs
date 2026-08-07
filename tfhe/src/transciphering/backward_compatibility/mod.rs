use tfhe_versionable::VersionsDispatch;

use crate::transciphering::{
    AesIv, CompressedTranscipheringServerKey, KreyviumIV, OneTimePadFheSecretMask,
    OneTimePadPlainSecretMask, SerializableAesFheKey, SerializableKreyviumFheKey, StreamCipherKind,
    StreamCiphertext, TranscipheringPrivateKey, TranscipheringServerKey,
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
pub enum SerializableAesFheKeyVersions {
    V0(SerializableAesFheKey),
}

#[derive(VersionsDispatch)]
pub enum AesIvVersions {
    V0(AesIv),
}

#[derive(VersionsDispatch)]
pub enum OneTimePadFheSecretMaskVersions {
    V0(OneTimePadFheSecretMask),
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
