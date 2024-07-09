use tfhe_versionable::VersionsDispatch;

use crate::boolean::ciphertext::{Ciphertext, CompressedCiphertext};

#[derive(VersionsDispatch)]
pub enum CiphertextVersions {
    V0(Ciphertext),
}

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextVersions {
    V0(CompressedCiphertext),
}
