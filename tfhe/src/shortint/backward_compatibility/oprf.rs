use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::shortint::oprf::{
    AtomicPatternOprfPrivateKey, CompressedAtomicPatternOprfServerKey,
    CompressedOprfBootstrappingKey, CompressedOprfServerKey, GenericAtomicPatternOprfServerKey,
    GenericOprfServerKey, OprfBootstrappingKey, OprfPrivateKey,
};
use tfhe_fft::c64;

#[derive(VersionsDispatch)]

pub enum OprfBootstrappingKeyVersions<C: Container<Element = c64>> {
    V0(OprfBootstrappingKey<C>),
}

#[derive(VersionsDispatch)]
pub enum AtomicPatternOprfPrivateKeyVersions {
    V0(AtomicPatternOprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum OprfPrivateKeyVersions {
    V0(OprfPrivateKey),
}

#[derive(VersionsDispatch)]

pub enum AtomicPatternOprfServerKeyVersions<C: Container<Element = c64>> {
    V0(GenericAtomicPatternOprfServerKey<C>),
}

#[derive(VersionsDispatch)]
pub enum OprfServerKeyVersions<C: Container<Element = c64>> {
    V0(GenericOprfServerKey<C>),
}

#[derive(VersionsDispatch)]

pub enum CompressedOprfBootstrappingKeyVersions {
    V0(CompressedOprfBootstrappingKey),
}

#[derive(VersionsDispatch)]

pub enum CompressedAtomicPatternOprfServerKeyVersions {
    V0(CompressedAtomicPatternOprfServerKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
