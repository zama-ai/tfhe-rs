use tfhe_versionable::VersionsDispatch;

use super::TranscipheringCipherKind;

#[derive(VersionsDispatch)]
pub enum TranscipheringCipherKindVersions {
    V0(TranscipheringCipherKind),
}
