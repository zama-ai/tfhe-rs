use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Cleartext, Numeric};

#[derive(VersionsDispatch)]
pub enum CleartextVersions<T: Numeric> {
    V0(Cleartext<T>),
}
