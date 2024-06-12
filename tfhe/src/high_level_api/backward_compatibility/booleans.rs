use serde::{Deserialize, Serialize};
use tfhe_versionable::VersionsDispatch;

use crate::high_level_api::booleans::InnerBooleanVersionOwned;
use crate::{CompactFheBool, CompactFheBoolList, CompressedFheBool, FheBool};

// Manual impl
#[derive(Serialize, Deserialize)]
pub(crate) enum InnerBooleanVersionedOwned {
    V0(InnerBooleanVersionOwned),
}

#[derive(VersionsDispatch)]
pub enum FheBoolVersions {
    V0(FheBool),
}

#[derive(VersionsDispatch)]
pub enum CompressedFheBoolVersions {
    V0(CompressedFheBool),
}

#[derive(VersionsDispatch)]
pub enum CompactFheBoolVersions {
    V0(CompactFheBool),
}

#[derive(VersionsDispatch)]
pub enum CompactFheBoolListVersions {
    V0(CompactFheBoolList),
}
