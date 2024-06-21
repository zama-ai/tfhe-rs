use serde::{Deserialize, Serialize};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::high_level_api::keys::*;

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKey),
}

#[derive(Serialize)]
pub enum ServerKeyVersioned<'vers> {
    V0(ServerKeyVersion<'vers>),
}

#[derive(Serialize, Deserialize)]
pub enum ServerKeyVersionedOwned {
    V0(ServerKeyVersionOwned),
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(CompressedServerKey),
}

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyVersions {
    V0(CompactPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPublicKeyVersions {
    V0(CompressedCompactPublicKey),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerConfigVersions {
    V0(IntegerConfig),
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV0 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

impl Upgrade<IntegerClientKey> for IntegerClientKeyV0 {
    fn upgrade(self) -> Result<IntegerClientKey, String> {
        Ok(IntegerClientKey {
            key: self.key,
            wopbs_block_parameters: self.wopbs_block_parameters,
            dedicated_compact_private_key: None,
            compression_key: None,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerClientKeyVersions {
    V0(IntegerClientKeyV0),
    V1(IntegerClientKey),
}

#[derive(VersionsDispatch)]
pub enum IntegerServerKeyVersions {
    V0(IntegerServerKey),
}

#[derive(VersionsDispatch)]
pub enum IntegerCompressedServerKeyVersions {
    V0(IntegerCompressedServerKey),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(in crate::high_level_api) enum IntegerCompactPublicKeyVersions {
    V0(IntegerCompactPublicKey),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(in crate::high_level_api) enum IntegerCompressedCompactPublicKeyVersions {
    V0(IntegerCompressedCompactPublicKey),
}
