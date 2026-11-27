use tfhe_versionable::VersionsDispatch;

use crate::integer::{ClientKey, RadixClientKey};

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}

#[derive(VersionsDispatch)]
pub enum RadixClientKeyVersions {
    V0(RadixClientKey),
}
