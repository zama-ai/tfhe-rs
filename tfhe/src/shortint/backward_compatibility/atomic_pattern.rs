use tfhe_versionable::VersionsDispatch;

use crate::shortint::AtomicPatternKind;

#[derive(VersionsDispatch)]
pub enum AtomicPatternKindVersions {
    V0(AtomicPatternKind),
}
