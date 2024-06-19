use tfhe_versionable::VersionsDispatch;

use crate::CompactCiphertextList;

#[derive(VersionsDispatch)]
pub enum CompactCiphertextListVersions {
    V0(CompactCiphertextList),
}
