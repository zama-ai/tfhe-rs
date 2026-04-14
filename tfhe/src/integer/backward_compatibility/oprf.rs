use tfhe_versionable::VersionsDispatch;

use crate::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey, OprfServerKey};

#[derive(VersionsDispatch)]
pub enum OprfPrivateKeyVersions {
    V0(OprfPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum OprfServerKeyVersions {
    V0(OprfServerKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedOprfServerKeyVersions {
    V0(CompressedOprfServerKey),
}
