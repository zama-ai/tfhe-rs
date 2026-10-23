use tfhe_versionable::VersionsDispatch;

#[cfg(feature = "experimental")]
use crate::integer::CrtClientKey;
use crate::integer::{ClientKey, RadixClientKey};

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}

#[cfg(feature = "experimental")]
#[derive(VersionsDispatch)]
pub enum CrtClientKeyVersions {
    V0(CrtClientKey),
}

#[derive(VersionsDispatch)]
pub enum RadixClientKeyVersions {
    V0(RadixClientKey),
}
