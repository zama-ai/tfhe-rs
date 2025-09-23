use tfhe_versionable::VersionsDispatch;

use crate::high_level_api::xof_key_set::{CompressedXofKeySet, XofKeySet};

#[derive(VersionsDispatch)]
pub enum CompressedXofKeySetVersions {
    V0(CompressedXofKeySet),
}

#[derive(VersionsDispatch)]
pub enum XofKeySetVersions {
    V0(XofKeySet),
}
