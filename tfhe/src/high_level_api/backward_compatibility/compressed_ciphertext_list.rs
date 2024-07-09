use tfhe_versionable::VersionsDispatch;

use crate::CompressedCiphertextList;

#[derive(VersionsDispatch)]
pub enum CompressedCiphertextListVersions {
    V0(CompressedCiphertextList),
}
