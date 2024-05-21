use tfhe_versionable::VersionsDispatch;

use crate::shortint::ClientKey;

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}
