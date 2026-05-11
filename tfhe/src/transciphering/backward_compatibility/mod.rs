use tfhe_versionable::VersionsDispatch;

use crate::transciphering::{StreamCipherKind, StreamCiphertext};

#[derive(VersionsDispatch)]
pub enum StreamCipherKindVersions {
    V0(StreamCipherKind),
}

#[derive(VersionsDispatch)]
pub enum StreamCiphertextVersions {
    V0(StreamCiphertext),
}
