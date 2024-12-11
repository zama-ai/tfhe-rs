use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, GswCiphertext};

#[derive(VersionsDispatch)]
pub enum GswCiphertextVersions<C: Container> {
    V0(GswCiphertext<C>),
}
