use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::Container;
use crate::shortint::server_key::*;
use std::convert::Infallible;
use tfhe_versionable::deprecation::{Deprecable, Deprecated};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
pub enum SerializableShortintBootstrappingKeyV0<C: Container<Element = tfhe_fft::c64>> {
    Classic(FourierLweBootstrapKey<C>),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl<C: Container<Element = tfhe_fft::c64>> Upgrade<SerializableShortintBootstrappingKey<C>>
    for SerializableShortintBootstrappingKeyV0<C>
{
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializableShortintBootstrappingKey<C>, Self::Error> {
        Ok(match self {
            Self::Classic(bsk) => SerializableShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: None,
            },
            Self::MultiBit {
                fourier_bsk,
                deterministic_execution,
            } => SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                deterministic_execution,
            },
        })
    }
}

#[derive(VersionsDispatch)]
pub enum SerializableShortintBootstrappingKeyVersions<C: Container<Element = tfhe_fft::c64>> {
    V0(SerializableShortintBootstrappingKeyV0<C>),
    V1(SerializableShortintBootstrappingKey<C>),
}

impl Deprecable for ServerKey {
    const TYPE_NAME: &'static str = "ServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions {
    V0(Deprecated<ServerKey>),
    V1(ServerKey),
}

impl Deprecable for ShortintCompressedBootstrappingKey {
    const TYPE_NAME: &'static str = "ShortintCompressedBootstrappingKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub enum ShortintCompressedBootstrappingKeyV1 {
    Classic(SeededLweBootstrapKeyOwned<u64>),
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl Upgrade<ShortintCompressedBootstrappingKey> for ShortintCompressedBootstrappingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ShortintCompressedBootstrappingKey, Self::Error> {
        Ok(match self {
            Self::Classic(seeded_lwe_bootstrap_key) => {
                ShortintCompressedBootstrappingKey::Classic {
                    bsk: seeded_lwe_bootstrap_key,
                    modulus_switch_noise_reduction_key: None,
                }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => ShortintCompressedBootstrappingKey::MultiBit {
                seeded_bsk,
                deterministic_execution,
            },
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ShortintCompressedBootstrappingKeyVersions {
    V0(Deprecated<ShortintCompressedBootstrappingKey>),
    V1(ShortintCompressedBootstrappingKeyV1),
    V2(ShortintCompressedBootstrappingKey),
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
