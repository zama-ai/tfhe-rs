use tfhe_versionable::VersionsDispatch;

use crate::integer::{
    CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey,
};
use tfhe_core_crypto::prelude::Container;

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyVersions {
    V0(CompactPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompactPrivateKeyVersions<KeyCont: Container<Element = u64>> {
    V0(CompactPrivateKey<KeyCont>),
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPublicKeyVersions {
    V0(CompressedCompactPublicKey),
}
