use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, PlaintextList};

#[derive(VersionsDispatch)]
pub enum PlaintextListVersions<C: Container> {
    V0(PlaintextList<C>),
}
