use tfhe_versionable::VersionsDispatch;

use crate::shortint::client_key::atomic_pattern::{
    AtomicPatternClientKey, KS32AtomicPatternClientKey, StandardAtomicPatternClientKey,
};

#[derive(VersionsDispatch)]
pub enum AtomicPatternClientKeyVersions {
    V0(AtomicPatternClientKey),
}

#[derive(VersionsDispatch)]
pub enum StandardAtomicPatternClientKeyVersions {
    V0(StandardAtomicPatternClientKey),
}

#[derive(VersionsDispatch)]
pub enum KS32AtomicPatternClientKeyVersions {
    V0(KS32AtomicPatternClientKey),
}
