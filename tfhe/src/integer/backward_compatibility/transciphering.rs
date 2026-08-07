use tfhe_versionable::VersionsDispatch;

use crate::integer::transciphering::{IntegerStreamCiphertext, IntegerStreamCiphertextKind};

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextKindVersions {
    V0(IntegerStreamCiphertextKind),
}

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextVersions {
    V0(IntegerStreamCiphertext),
}
