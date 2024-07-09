use tfhe_versionable::VersionsDispatch;

use crate::integer::{ClientKey, CrtClientKey, RadixClientKey};

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}

#[derive(VersionsDispatch)]
pub enum CrtClientKeyVersions {
    V0(CrtClientKey),
}

#[derive(VersionsDispatch)]
pub enum RadixClientKeyVersions {
    V0(RadixClientKey),
}
