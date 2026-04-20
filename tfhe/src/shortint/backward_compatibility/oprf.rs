use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::shortint::oprf::{
    AtomicPatternOprfPrivateKey, CompressedOprfBootstrappingKey, CompressedOprfServerKey,
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
pub enum GenericOprfServerKeyVersions<C: Container<Element = c64>> {
    V0(GenericOprfServerKey<C>),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfBootstrappingKeyVersions {
    V0(CompressedOprfBootstrappingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
