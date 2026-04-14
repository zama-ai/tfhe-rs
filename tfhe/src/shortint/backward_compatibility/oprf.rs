use tfhe_versionable::VersionsDispatch;

use crate::shortint::oprf::{
    AtomicPatternOprfPrivateKey, CompressedOprfServerKey, GenericOprfServerKey, OprfPrivateKey,
};

#[derive(VersionsDispatch)]
pub enum AtomicPatternOprfPrivateKeyVersions {
    V0(AtomicPatternOprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum OprfPrivateKeyVersions {
    V0(OprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum GenericOprfServerKeyVersions<K> {
    V0(GenericOprfServerKey<K>),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
