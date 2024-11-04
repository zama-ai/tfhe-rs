use crate::high_level_api::keys::*;
use crate::Tag;
use std::convert::Infallible;
use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum ClientKeyVersions {
    V0(ClientKeyV0),
    V1(ClientKey),
}

#[derive(Version)]
pub struct ClientKeyV0 {
    pub(crate) key: IntegerClientKey,
}

impl Upgrade<ClientKey> for ClientKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ClientKey, Self::Error> {
        let Self { key } = self;
        Ok(ClientKey {
            key,
            tag: Tag::default(),
        })
    }
}

impl Deprecable for ServerKey {
    const TYPE_NAME: &'static str = "ServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(Deprecated<ServerKey>),
    V1(Deprecated<ServerKey>),
    V2(Deprecated<ServerKey>),
    V3(ServerKey),
}

impl Deprecable for CompressedServerKey {
    const TYPE_NAME: &'static str = "CompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(Deprecated<CompressedServerKey>),
    V1(Deprecated<CompressedServerKey>),
    V2(CompressedServerKey),
}

#[derive(Version)]
pub struct PublicKeyV0 {
    pub(in crate::high_level_api) key: crate::integer::PublicKey,
}

impl Upgrade<PublicKey> for PublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<PublicKey, Self::Error> {
        Ok(PublicKey {
            key: self.key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum PublicKeyVersions {
    V0(PublicKeyV0),
    V1(PublicKey),
}

#[derive(Version)]
pub struct CompactPublicKeyV0 {
    pub(in crate::high_level_api) key: IntegerCompactPublicKey,
}

impl Upgrade<CompactPublicKey> for CompactPublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompactPublicKey, Self::Error> {
        Ok(CompactPublicKey {
            key: self.key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompactPublicKeyVersions {
    V0(CompactPublicKeyV0),
    V1(CompactPublicKey),
}

#[derive(Version)]
pub struct CompressedPublicKeyV0 {
    pub(in crate::high_level_api) key: crate::integer::CompressedPublicKey,
}

impl Upgrade<CompressedPublicKey> for CompressedPublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedPublicKey, Self::Error> {
        Ok(CompressedPublicKey {
            key: self.key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedPublicKeyVersions {
    V0(CompressedPublicKeyV0),
    V1(CompressedPublicKey),
}

#[derive(Version)]
pub struct CompressedCompactPublicKeyV0 {
    pub(in crate::high_level_api) key: IntegerCompressedCompactPublicKey,
}

impl Upgrade<CompressedCompactPublicKey> for CompressedCompactPublicKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedCompactPublicKey, Self::Error> {
        Ok(CompressedCompactPublicKey {
            key: self.key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedCompactPublicKeyVersions {
    V0(CompressedCompactPublicKeyV0),
    V1(CompressedCompactPublicKey),
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerConfigVersions {
    V0(IntegerConfig),
}

impl Deprecable for IntegerClientKey {
    const TYPE_NAME: &'static str = "IntegerClientKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.8";
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV2 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<crate::shortint::list_compression::CompressionPrivateKeys>,
}

impl Upgrade<IntegerClientKey> for IntegerClientKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKey, Self::Error> {
        Ok(IntegerClientKey {
            key: self.key,
            dedicated_compact_private_key: self.dedicated_compact_private_key,
            compression_key: self
                .compression_key
                .map(|key| crate::integer::compression_keys::CompressionPrivateKeys { key }),
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerClientKeyVersions {
    V0(Deprecated<IntegerClientKey>),
    V1(Deprecated<IntegerClientKey>),
    V2(IntegerClientKeyV2),
    V3(IntegerClientKey),
}

impl Deprecable for IntegerServerKey {
    const TYPE_NAME: &'static str = "IntegerServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum IntegerServerKeyVersions {
    V0(Deprecated<IntegerServerKey>),
    V1(Deprecated<IntegerServerKey>),
    V2(Deprecated<IntegerServerKey>),
    V3(Deprecated<IntegerServerKey>),
    V4(IntegerServerKey),
}

impl Deprecable for IntegerCompressedServerKey {
    const TYPE_NAME: &'static str = "IntegerCompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum IntegerCompressedServerKeyVersions {
    V0(Deprecated<IntegerCompressedServerKey>),
    V1(Deprecated<IntegerCompressedServerKey>),
    V2(IntegerCompressedServerKey),
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

impl Deprecable for KeySwitchingKey {
    const TYPE_NAME: &'static str = "KeySwitchingKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(Deprecated<KeySwitchingKey>),
    V1(KeySwitchingKey),
}
