use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::Container;
use crate::integer::{CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey};

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyVersions {
    V0(CompactPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompactPrivateKeyVersions<KeyCont: Container<Element = u64>> {
    V0(CompactPrivateKey<KeyCont>),
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPublicKeyVersions {
    V0(CompressedCompactPublicKey),
}
