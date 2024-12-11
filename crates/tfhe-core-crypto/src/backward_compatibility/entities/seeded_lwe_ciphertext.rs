use tfhe_versionable::VersionsDispatch;

use crate::prelude::{SeededLweCiphertext, UnsignedInteger};

#[derive(VersionsDispatch)]
pub enum SeededLweCiphertextVersions<Scalar: UnsignedInteger> {
    V0(SeededLweCiphertext<Scalar>),
}
