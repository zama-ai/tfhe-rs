use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, PlaintextList};

#[derive(VersionsDispatch)]
pub enum PlaintextListVersions<C: Container> {
    V0(PlaintextList<C>),
}
