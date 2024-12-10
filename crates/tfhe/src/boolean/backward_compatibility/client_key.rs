use tfhe_versionable::VersionsDispatch;

use crate::boolean::client_key::ClientKey;

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}
