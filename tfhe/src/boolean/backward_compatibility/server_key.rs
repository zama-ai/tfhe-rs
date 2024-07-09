use tfhe_versionable::VersionsDispatch;

use crate::boolean::server_key::{CompressedServerKey, ServerKey};

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(ServerKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(CompressedServerKey),
}
