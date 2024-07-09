use tfhe_versionable::VersionsDispatch;

use crate::boolean::public_key::{CompressedPublicKey, PublicKey};

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKey),
}
