use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressedNoiseSquashingCompressionKey,
    CompressionKey, CompressionPrivateKeys, DecompressionKey, NoiseSquashingCompressionKey,
    NoiseSquashingCompressionPrivateKey,
};
use crate::shortint::parameters::LweCiphertextCount;
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::Error;
use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum CompressionKeyVersions {
    V0(CompressionKey),
}

#[derive(Version)]
pub struct DecompressionKeyV0 {
    pub blind_rotate_key: ShortintBootstrappingKey<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl Upgrade<DecompressionKey> for DecompressionKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<DecompressionKey, Self::Error> {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        match blind_rotate_key {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: _,
            } => Ok(DecompressionKey {
                blind_rotate_key: bsk,
                lwe_per_glwe,
            }),
            ShortintBootstrappingKey::MultiBit { .. } => Err(Error::new(
                "DecompressionKey should not have a MultiBit bootstrap key".to_owned(),
            )),
        }
    }
}

#[derive(VersionsDispatch)]
pub enum DecompressionKeyVersions {
    V0(DecompressionKeyV0),
    V1(DecompressionKey),
}

impl Deprecable for CompressedCompressionKey {
    const TYPE_NAME: &'static str = "CompressedCompressionKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedCompressionKeyVersions {
    V0(Deprecated<CompressedCompressionKey>),
    V1(Deprecated<CompressedCompressionKey>),
    V2(CompressedCompressionKey),
}

impl Deprecable for CompressedDecompressionKey {
    const TYPE_NAME: &'static str = "CompressedDecompressionKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum CompressedDecompressionKeyVersions {
    V0(Deprecated<CompressedDecompressionKey>),
    V1(CompressedDecompressionKey),
}

#[derive(VersionsDispatch)]
pub enum CompressionPrivateKeysVersions {
    V0(CompressionPrivateKeys),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionKeyVersions {
    V0(NoiseSquashingCompressionKey),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionPrivateKeyVersions {
    V0(NoiseSquashingCompressionPrivateKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingCompressionKeyVersions {
    V0(CompressedNoiseSquashingCompressionKey),
}
