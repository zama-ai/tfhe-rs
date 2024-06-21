use tfhe_versionable::VersionsDispatch;

use crate::integer::ClientKey;

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}
