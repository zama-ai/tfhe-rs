use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::integer::oprf::{CompressedOprfServerKey, GenericOprfServerKey, OprfPrivateKey};
use tfhe_fft::c64;

#[derive(VersionsDispatch)]
pub enum OprfPrivateKeyVersions {
    V0(OprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum OprfServerKeyVersions<C: Container<Element = c64>> {
    V0(GenericOprfServerKey<C>),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
