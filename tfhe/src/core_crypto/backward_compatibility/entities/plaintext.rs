use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Numeric, Plaintext};

#[derive(VersionsDispatch)]
pub enum PlaintextVersions<T: Numeric> {
    V0(Plaintext<T>),
}
