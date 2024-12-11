use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Numeric, Plaintext};

#[derive(VersionsDispatch)]
pub enum PlaintextVersions<T: Numeric> {
    V0(Plaintext<T>),
}
