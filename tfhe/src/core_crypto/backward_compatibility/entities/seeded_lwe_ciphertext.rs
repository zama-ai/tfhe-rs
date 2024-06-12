use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{SeededLweCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(SeededLweCiphertext<Scalar>),
}
