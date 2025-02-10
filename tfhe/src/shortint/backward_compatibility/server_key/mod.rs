pub mod modulus_switch_noise_reduction;

use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{Container, PBSOrder};
use crate::shortint::atomic_pattern::{AtomicPatternServerKey, ClassicalAtomicPatternServerKey};
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::server_key::*;
use crate::shortint::{CarryModulus, CiphertextModulus, MaxNoiseLevel, MessageModulus};
use crate::Error;

use std::any::{Any, TypeId};
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

#[derive(Version)]
pub struct ServerKeyV1 {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

impl<AP: Clone + 'static> Upgrade<GenericServerKey<AP>> for ServerKeyV1 {
    type Error = Error;

    fn upgrade(self) -> Result<GenericServerKey<AP>, Self::Error> {
        let classical_ap = ClassicalAtomicPatternServerKey::from_raw_parts(
            self.key_switching_key,
            self.bootstrapping_key,
            self.pbs_order,
        );

        if TypeId::of::<AP>() == TypeId::of::<AtomicPatternServerKey>() {
            let ap = AtomicPatternServerKey::Classical(classical_ap);
            let sk = ServerKey::from_raw_parts(
                ap,
                self.message_modulus,
                self.carry_modulus,
                self.max_degree,
                self.max_noise_level,
            );
            Ok((&sk as &dyn Any)
                .downcast_ref::<GenericServerKey<AP>>()
                .unwrap() // We know from the TypeId that AP is of the right type so we can unwrap
                .clone())
        } else if TypeId::of::<AP>() == TypeId::of::<ClassicalAtomicPatternServerKey>() {
            let sk = ClassicalServerKey::from_raw_parts(
                classical_ap,
                self.message_modulus,
                self.carry_modulus,
                self.max_degree,
                self.max_noise_level,
            );
            Ok((&sk as &dyn Any)
                .downcast_ref::<GenericServerKey<AP>>()
                .unwrap() // We know from the TypeId that AP is of the right type so we can unwrap
                .clone())
        } else {
            Err(Error::new(
                "ServerKey from TFHE-rs 1.0 and before can only be deserialized to the classical \
Atomic Pattern"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum ServerKeyVersions<AP> {
    V0(Deprecated<ServerKey>),
    V1(ServerKeyV1),
    V2(GenericServerKey<AP>),
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
