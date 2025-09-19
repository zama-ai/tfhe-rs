use crate::high_level_api::keys::*;
use crate::integer::ciphertext::{
    CompressedNoiseSquashingCompressionKey, NoiseSquashingCompressionKey,
    NoiseSquashingCompressionPrivateKey,
};
use crate::integer::compression_keys::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressionKey, CompressionPrivateKeys,
    DecompressionKey,
};
use crate::integer::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
};
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

impl Upgrade<IntegerClientKeyV3> for IntegerClientKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKeyV3, Self::Error> {
        Ok(IntegerClientKeyV3 {
            key: self.key,
            dedicated_compact_private_key: self.dedicated_compact_private_key,
            compression_key: self
                .compression_key
                .map(|key| crate::integer::compression_keys::CompressionPrivateKeys { key }),
        })
    }
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV3 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<crate::integer::compression_keys::CompressionPrivateKeys>,
}

impl Upgrade<IntegerClientKeyV4> for IntegerClientKeyV3 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKeyV4, Self::Error> {
        let Self {
            key,
            dedicated_compact_private_key,
            compression_key,
        } = self;

        Ok(IntegerClientKeyV4 {
            key,
            dedicated_compact_private_key,
            compression_key,
            noise_squashing_private_key: None,
        })
    }
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV4 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<CompressionPrivateKeys>,
    pub(crate) noise_squashing_private_key: Option<NoiseSquashingPrivateKey>,
}

impl Upgrade<IntegerClientKeyV5> for IntegerClientKeyV4 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKeyV5, Self::Error> {
        let Self {
            key,
            dedicated_compact_private_key,
            compression_key,
            noise_squashing_private_key,
        } = self;

        Ok(IntegerClientKeyV5 {
            key,
            dedicated_compact_private_key,
            compression_key,
            noise_squashing_private_key,
            noise_squashing_compression_private_key: None,
        })
    }
}

#[derive(Version)]
pub(crate) struct IntegerClientKeyV5 {
    pub(crate) key: crate::integer::ClientKey,
    pub(crate) dedicated_compact_private_key: Option<CompactPrivateKey>,
    pub(crate) compression_key: Option<CompressionPrivateKeys>,
    pub(crate) noise_squashing_private_key: Option<NoiseSquashingPrivateKey>,
    pub(crate) noise_squashing_compression_private_key: Option<NoiseSquashingCompressionPrivateKey>,
}

#[derive(VersionsDispatch)]
#[allow(unused)]
pub(crate) enum IntegerClientKeyVersions {
    V0(Deprecated<IntegerClientKey>),
    V1(Deprecated<IntegerClientKey>),
    V2(IntegerClientKeyV2),
    V3(IntegerClientKeyV3),
    V4(IntegerClientKeyV4),
    V5(IntegerClientKeyV5),
    V6(IntegerClientKey),
}

impl Upgrade<IntegerClientKey> for IntegerClientKeyV5 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerClientKey, Self::Error> {
        let Self {
            key,
            dedicated_compact_private_key,
            compression_key,
            noise_squashing_private_key,
            noise_squashing_compression_private_key,
        } = self;

        Ok(IntegerClientKey {
            key,
            dedicated_compact_private_key,
            compression_key,
            noise_squashing_private_key,
            noise_squashing_compression_private_key,
            cpk_re_randomization_ksk_params: None,
        })
    }
}

impl Deprecable for IntegerServerKey {
    const TYPE_NAME: &'static str = "IntegerServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct IntegerServerKeyV4 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressionKey>,
    pub(crate) decompression_key: Option<DecompressionKey>,
}

impl Upgrade<IntegerServerKeyV5> for IntegerServerKeyV4 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKeyV5, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = self;

        Ok(IntegerServerKeyV5 {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key: None,
        })
    }
}

#[derive(Version)]
pub struct IntegerServerKeyV5 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressionKey>,
    pub(crate) decompression_key: Option<DecompressionKey>,
    pub(crate) noise_squashing_key: Option<NoiseSquashingKey>,
}

impl Upgrade<IntegerServerKeyV6> for IntegerServerKeyV5 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKeyV6, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
        } = self;

        Ok(IntegerServerKeyV6 {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key: None,
        })
    }
}

#[derive(Version)]
pub struct IntegerServerKeyV6 {
    pub(crate) key: crate::integer::ServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::KeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressionKey>,
    pub(crate) decompression_key: Option<DecompressionKey>,
    pub(crate) noise_squashing_key: Option<NoiseSquashingKey>,
    pub(crate) noise_squashing_compression_key: Option<NoiseSquashingCompressionKey>,
}

impl Upgrade<IntegerServerKey> for IntegerServerKeyV6 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerServerKey, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
        } = self;

        Ok(IntegerServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material: None,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerServerKeyVersions {
    V0(Deprecated<IntegerServerKey>),
    V1(Deprecated<IntegerServerKey>),
    V2(Deprecated<IntegerServerKey>),
    V3(Deprecated<IntegerServerKey>),
    V4(IntegerServerKeyV4),
    V5(IntegerServerKeyV5),
    V6(IntegerServerKeyV6),
    V7(IntegerServerKey),
}

impl Deprecable for IntegerCompressedServerKey {
    const TYPE_NAME: &'static str = "IntegerCompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct IntegerCompressedServerKeyV2 {
    pub(crate) key: crate::integer::CompressedServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressedCompressionKey>,
    pub(crate) decompression_key: Option<CompressedDecompressionKey>,
}

impl Upgrade<IntegerCompressedServerKeyV3> for IntegerCompressedServerKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerCompressedServerKeyV3, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
        } = self;

        Ok(IntegerCompressedServerKeyV3 {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key: None,
        })
    }
}

#[derive(Version)]
pub struct IntegerCompressedServerKeyV3 {
    pub(crate) key: crate::integer::CompressedServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressedCompressionKey>,
    pub(crate) decompression_key: Option<CompressedDecompressionKey>,
    pub(crate) noise_squashing_key: Option<CompressedNoiseSquashingKey>,
}

impl Upgrade<IntegerCompressedServerKeyV4> for IntegerCompressedServerKeyV3 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerCompressedServerKeyV4, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
        } = self;

        Ok(IntegerCompressedServerKeyV4 {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key: None,
        })
    }
}

#[derive(Version)]
pub struct IntegerCompressedServerKeyV4 {
    pub(crate) key: crate::integer::CompressedServerKey,
    pub(crate) cpk_key_switching_key_material:
        Option<crate::integer::key_switching_key::CompressedKeySwitchingKeyMaterial>,
    pub(crate) compression_key: Option<CompressedCompressionKey>,
    pub(crate) decompression_key: Option<CompressedDecompressionKey>,
    pub(crate) noise_squashing_key: Option<CompressedNoiseSquashingKey>,
    pub(crate) noise_squashing_compression_key: Option<CompressedNoiseSquashingCompressionKey>,
}

impl Upgrade<IntegerCompressedServerKey> for IntegerCompressedServerKeyV4 {
    type Error = Infallible;

    fn upgrade(self) -> Result<IntegerCompressedServerKey, Self::Error> {
        let Self {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
        } = self;

        Ok(IntegerCompressedServerKey {
            key,
            cpk_key_switching_key_material,
            compression_key,
            decompression_key,
            noise_squashing_key,
            noise_squashing_compression_key,
            cpk_re_randomization_key_switching_key_material: None,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum IntegerCompressedServerKeyVersions {
    V0(Deprecated<IntegerCompressedServerKey>),
    V1(Deprecated<IntegerCompressedServerKey>),
    V2(IntegerCompressedServerKeyV2),
    V3(IntegerCompressedServerKeyV3),
    V4(IntegerCompressedServerKeyV4),
    V5(IntegerCompressedServerKey),
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

#[derive(VersionsDispatch)]
pub enum ReRandomizationKeySwitchingKeyVersions {
    V0(ReRandomizationKeySwitchingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedReRandomizationKeySwitchingKeyVersions {
    V0(CompressedReRandomizationKeySwitchingKey),
}
