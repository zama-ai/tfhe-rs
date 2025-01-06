use crate::strings::ciphertext::{FheAsciiChar, FheString};
use tfhe_versionable::VersionsDispatch;

#[derive(VersionsDispatch)]
pub enum FheAsciiCharVersions {
    V0(FheAsciiChar),
}

#[derive(VersionsDispatch)]
pub enum FheStringVersions {
    V0(FheString),
}
