use serde::{Deserialize, Serialize};
use tfhe_versionable::VersionsDispatch;

use crate::high_level_api::xof_key_set::{CompressedXofKeySet, XofKeySet};

#[derive(Serialize)]
pub enum CompressedXofKeySetVersioned<'vers> {
    V0(&'vers CompressedXofKeySet),
}

#[derive(Serialize, Deserialize)]
pub enum CompressedXofKeySetVersionedOwned {
    V0(CompressedXofKeySet),
}

#[derive(VersionsDispatch)]
pub enum XofKeySetVersions {
    V0(XofKeySet),
}
