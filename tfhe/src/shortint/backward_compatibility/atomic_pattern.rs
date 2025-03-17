use tfhe_versionable::VersionsDispatch;

use crate::shortint::atomic_pattern::{
    AtomicPatternServerKey, KS32AtomicPatternServerKey, StandardAtomicPatternServerKey,
};
use crate::shortint::{AtomicPatternKind, AtomicPatternParameters};

#[derive(VersionsDispatch)]
pub enum AtomicPatternKindVersions {
    V0(AtomicPatternKind),
}

#[derive(VersionsDispatch)]
pub enum AtomicPatternParametersVersions {
    V0(AtomicPatternParameters),
}

#[derive(VersionsDispatch)]
pub enum AtomicPatternServerKeyVersions {
    V0(AtomicPatternServerKey),
}

#[derive(VersionsDispatch)]
pub enum StandardAtomicPatternServerKeyVersions {
    V0(StandardAtomicPatternServerKey),
}

#[derive(VersionsDispatch)]
pub enum KS32AtomicPatternServerKeyVersions {
    V0(KS32AtomicPatternServerKey),
}
