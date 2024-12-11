use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, GlweSecretKey};

#[derive(VersionsDispatch)]
pub enum GlweSecretKeyVersions<C: Container> {
    V0(GlweSecretKey<C>),
}
