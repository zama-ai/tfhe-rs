use std::convert::Infallible;

use crate::core_crypto::prelude::{FourierLweBootstrapKeyOwned, SeededLweBootstrapKeyOwned};
use crate::shortint::list_compression::{
    CompressedCompressionKey, CompressedDecompressionKey, CompressedNoiseSquashingCompressionKey,
    CompressionKey, CompressionPrivateKeys, DecompressionKey, NoiseSquashingCompressionKey,
    NoiseSquashingCompressionPrivateKey,
};
use crate::shortint::parameters::LweCiphertextCount;
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ModulusSwitchConfiguration, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
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

impl Upgrade<DecompressionKeyV1> for DecompressionKeyV0 {
    type Error = Error;

    fn upgrade(self) -> Result<DecompressionKeyV1, Self::Error> {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        match blind_rotate_key {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: _,
            } => Ok(DecompressionKeyV1 {
                blind_rotate_key: bsk,
                lwe_per_glwe,
            }),
            ShortintBootstrappingKey::MultiBit { .. } => Err(Error::new(
                "DecompressionKey should not have a MultiBit bootstrap key".to_owned(),
            )),
        }
    }
}

#[derive(Version)]
pub struct DecompressionKeyV1 {
    pub blind_rotate_key: FourierLweBootstrapKeyOwned,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl Upgrade<DecompressionKey> for DecompressionKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<DecompressionKey, Self::Error> {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        Ok(DecompressionKey {
            bsk: ShortintBootstrappingKey::Classic {
                bsk: blind_rotate_key,
                modulus_switch_noise_reduction_key: ModulusSwitchConfiguration::Standard,
            },
            lwe_per_glwe,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum DecompressionKeyVersions {
    V0(DecompressionKeyV0),
    V1(DecompressionKeyV1),
    V2(DecompressionKey),
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

impl Deprecable for CompressedDecompressionKeyV1 {
    const TYPE_NAME: &'static str = "CompressedDecompressionKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct CompressedDecompressionKeyV1 {
    pub blind_rotate_key: SeededLweBootstrapKeyOwned<u64>,
    pub lwe_per_glwe: LweCiphertextCount,
}

impl Upgrade<CompressedDecompressionKey> for CompressedDecompressionKeyV1 {
    type Error = Error;

    fn upgrade(self) -> Result<CompressedDecompressionKey, Self::Error> {
        let Self {
            blind_rotate_key,
            lwe_per_glwe,
        } = self;

        Ok(CompressedDecompressionKey {
            bsk: ShortintCompressedBootstrappingKey::Classic {
                bsk: blind_rotate_key,
                modulus_switch_noise_reduction_key: CompressedModulusSwitchConfiguration::Standard,
            },
            lwe_per_glwe,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedDecompressionKeyVersions {
    V0(Deprecated<CompressedDecompressionKeyV1>),
    V1(CompressedDecompressionKeyV1),
    V2(CompressedDecompressionKey),
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
