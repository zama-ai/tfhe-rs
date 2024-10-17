use crate::high_level_api::keys::*;
use crate::Tag;
use std::convert::Infallible;
use std::sync::Arc;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
pub struct UnsupportedIntegerClientKeyV0;

#[derive(Version)]
pub struct UnsupportedIntegerClientKeyV1;

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

impl Upgrade<UnsupportedIntegerClientKeyV1> for UnsupportedIntegerClientKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<UnsupportedIntegerClientKeyV1, Self::Error> {
        Err(crate::Error::new(
            "Unable to load data this format is unsupported by this TFHE-rs version.".to_string(),
        ))
    }
}

impl Upgrade<IntegerClientKeyV2> for UnsupportedIntegerClientKeyV1 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<IntegerClientKeyV2, Self::Error> {
        Err(crate::Error::new(
            "Unable to load IntegerClientKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
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
    V0(UnsupportedIntegerClientKeyV0),
    V1(UnsupportedIntegerClientKeyV1),
    V2(IntegerClientKeyV2),
    V3(IntegerClientKey),
}

#[derive(Version)]
pub struct UnsupportedIntegerServerKeyV0;

#[derive(Version)]
pub struct UnsupportedIntegerServerKeyV1;

impl Upgrade<UnsupportedIntegerServerKeyV1> for UnsupportedIntegerServerKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<UnsupportedIntegerServerKeyV1, Self::Error> {
        Err(crate::Error::new(
            "Unable to load IntegerServerKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

impl Upgrade<IntegerServerKeyV2> for UnsupportedIntegerServerKeyV1 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<IntegerServerKeyV2, Self::Error> {
        Err(crate::Error::new(
            "Unable to load IntegerServerKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(Version)]
pub struct IntegerServerKeyV2 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<crate::shortint::list_compression::CompressionKey>,
    pub(crate) decompression_key: Option<crate::shortint::list_compression::DecompressionKey>,
}

impl Upgrade<IntegerServerKey> for IntegerServerKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKey, Self::Error> {
        Ok(IntegerServerKey {
            key: self.key,
            cpk_key_switching_key_material: self.cpk_key_switching_key_material,
            compression_key: self
                .compression_key
                .map(|key| crate::integer::compression_keys::CompressionKey { key }),
            decompression_key: self
                .decompression_key
                .map(|key| crate::integer::compression_keys::DecompressionKey { key }),
        })
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerServerKeyVersions {
    V0(UnsupportedIntegerServerKeyV0),
    V1(UnsupportedIntegerServerKeyV1),
    V2(IntegerServerKeyV2),
    V3(IntegerServerKey),
}

#[derive(Version)]
pub struct UnsupportedIntegerCompressedServerKeyV0;

impl Upgrade<IntegerCompressedServerKey> for UnsupportedIntegerCompressedServerKeyV0 {
    type Error = crate::Error;

    fn upgrade(self) -> Result<IntegerCompressedServerKey, Self::Error> {
        Err(crate::Error::new(
            "Unable to load IntegerCompressedServerKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerCompressedServerKeyVersions {
    V0(UnsupportedIntegerCompressedServerKeyV0),
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
