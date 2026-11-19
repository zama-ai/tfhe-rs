use tfhe_versionable::VersionsDispatch;

use crate::integer::transciphering::{
    IntegerStreamCiphertext, IntegerStreamCiphertextKind, IntegerStreamCiphertextList,
    IntegerStreamCiphertextPart,
};

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextKindVersions {
    V0(IntegerStreamCiphertextKind),
}

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextVersions {
    V0(IntegerStreamCiphertext),
}

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextPartVersions {
    V0(IntegerStreamCiphertextPart),
}

#[derive(VersionsDispatch)]
pub enum IntegerStreamCiphertextListVersions {
    V0(IntegerStreamCiphertextList),
}
