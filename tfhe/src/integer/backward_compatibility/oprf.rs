use tfhe_fft::c64;
use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::integer::oprf::{CompressedOprfServerKey, GenericOprfServerKey, OprfPrivateKey};

#[derive(VersionsDispatch)]
pub enum OprfPrivateKeyVersions {
    V0(OprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum GenericOprfServerKeyVersions<C: Container<Element = c64>> {
    V0(GenericOprfServerKey<C>),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
