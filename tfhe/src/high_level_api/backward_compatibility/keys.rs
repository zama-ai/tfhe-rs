use crate::high_level_api::keys::*;
use crate::shortint::list_compression::{CompressionKey, CompressionPrivateKeys, DecompressionKey};
use crate::Tag;
use std::convert::Infallible;
use std::sync::Arc;
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

// This type was previously versioned using a manual implementation with a conversion
// to a type where the inner key was name `integer_key`
#[derive(Version)]
pub struct ServerKeyV0 {
    pub(crate) integer_key: Arc<IntegerServerKey>,
}

impl Upgrade<ServerKeyV1> for ServerKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ServerKeyV1, Self::Error> {
        Ok(ServerKeyV1 {
            key: self.integer_key,
        })
    }
}

#[derive(Version)]
pub struct ServerKeyV1 {
    pub(crate) key: Arc<IntegerServerKey>,
}

impl Upgrade<ServerKey> for ServerKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ServerKey, Self::Error> {
        Ok(ServerKey {
            key: self.key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(ServerKeyV0),
    V1(ServerKeyV1),
    V2(ServerKey),
}

#[derive(Version)]
pub struct CompressedServerKeyV0 {
    pub(crate) integer_key: IntegerCompressedServerKey,
}

impl Upgrade<CompressedServerKey> for CompressedServerKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedServerKey, Self::Error> {
        Ok(CompressedServerKey {
            integer_key: self.integer_key,
            tag: Tag::default(),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(CompressedServerKeyV0),
    V1(CompressedServerKey),
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

#[derive(Version)]
pub(crate) struct IntegerClientKeyV0 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV1 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) wopbs_block_parameters: Option<crate::shortint::WopbsParameters>,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<CompressionPrivateKeys>,
}

impl Upgrade<IntegerClientKeyV1> for IntegerClientKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKeyV1, Self::Error> {
        Ok(IntegerClientKeyV1 {
            key: self.key,
            wopbs_block_parameters: self.wopbs_block_parameters,
            dedicated_compact_private_key: None,
            compression_key: None,
        })
    }
}

impl Upgrade<IntegerClientKey> for IntegerClientKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKey, Self::Error> {
        Ok(IntegerClientKey {
            key: self.key,
            dedicated_compact_private_key: self.dedicated_compact_private_key,
            compression_key: self.compression_key,
        })
    }
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerClientKeyVersions {
    V0(IntegerClientKeyV0),
    V1(IntegerClientKeyV1),
    V2(IntegerClientKey),
}

#[derive(Version)]
pub struct IntegerServerKeyV0 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
}

#[derive(Version)]
pub struct IntegerServerKeyV1 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) wopbs_key: Option<crate::integer::wopbs::WopbsKey>,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressionKey>,
    pub(crate) decompression_key: Option<DecompressionKey>,
}

impl Upgrade<IntegerServerKeyV1> for IntegerServerKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKeyV1, Self::Error> {
        Ok(IntegerServerKeyV1 {
            key: self.key,
            wopbs_key: self.wopbs_key,
            cpk_key_switching_key_material: None,
            compression_key: None,
            decompression_key: None,
        })
    }
}

impl Upgrade<IntegerServerKey> for IntegerServerKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKey, Self::Error> {
        Ok(IntegerServerKey {
            key: self.key,
            cpk_key_switching_key_material: self.cpk_key_switching_key_material,
            compression_key: self.compression_key,
            decompression_key: self.decompression_key,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerServerKeyVersions {
    V0(IntegerServerKeyV0),
    V1(IntegerServerKeyV1),
    V2(IntegerServerKey),
}

#[derive(Version)]
pub struct IntegerCompressedServerKeyV0 {
    pub(crate) key: crate::integer::CompressedServerKey,
}

impl Upgrade<IntegerCompressedServerKey> for IntegerCompressedServerKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerCompressedServerKey, Self::Error> {
        Ok(IntegerCompressedServerKey {
            key: self.key,
            cpk_key_switching_key_material: None,
            compression_key: None,
            decompression_key: None,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerCompressedServerKeyVersions {
    V0(IntegerCompressedServerKeyV0),
    V1(IntegerCompressedServerKey),
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

#[derive(VersionsDispatch)]
pub enum KeySwitchingKeyVersions {
    V0(KeySwitchingKey),
}
