use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, LweSecretKey};

#[derive(VersionsDispatch)]
pub enum LweSecretKeyVersions<C: Container> {
    V0(LweSecretKey<C>),
}
