pub mod modulus_switch_noise_reduction;

use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{Container, PBSOrder, UnsignedInteger};
use crate::shortint::atomic_pattern::compressed::{
    CompressedAtomicPatternServerKey, CompressedStandardAtomicPatternServerKey,
};
use crate::shortint::atomic_pattern::{AtomicPatternServerKey, StandardAtomicPatternServerKey};
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

impl<InputScalar, C: Container<Element = tfhe_fft::c64>>
    Upgrade<SerializableShortintBootstrappingKey<InputScalar, C>>
    for SerializableShortintBootstrappingKeyV0<C>
where
    InputScalar: UnsignedInteger,
{
    type Error = crate::Error;

    fn upgrade(self) -> Result<SerializableShortintBootstrappingKey<InputScalar, C>, Self::Error> {
        // Older keys can only have an InputScalar of u64
        if TypeId::of::<InputScalar>() != TypeId::of::<u64>() {
            return Err(crate::Error::new(format!(
                "Expected u64 as InputScalar while upgrading \
                SerializableShortintBootstrappingKey, got {}",
                std::any::type_name::<InputScalar>()
            )));
        }
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
pub enum SerializableShortintBootstrappingKeyVersions<
    InputScalar,
    C: Container<Element = tfhe_fft::c64>,
> where
    InputScalar: UnsignedInteger,
{
    V0(SerializableShortintBootstrappingKeyV0<C>),
    V1(SerializableShortintBootstrappingKey<InputScalar, C>),
}

impl Deprecable for ServerKey {
    const TYPE_NAME: &'static str = "ServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct ServerKeyV1 {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey<u64>,
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
        let std_ap = StandardAtomicPatternServerKey::from_raw_parts(
            self.key_switching_key,
            self.bootstrapping_key,
            self.pbs_order,
        );

        if TypeId::of::<AP>() == TypeId::of::<AtomicPatternServerKey>() {
            let ap = AtomicPatternServerKey::Standard(std_ap);
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
        } else if TypeId::of::<AP>() == TypeId::of::<StandardAtomicPatternServerKey>() {
            let sk = StandardServerKey::from_raw_parts(
                std_ap,
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

impl<InputScalar: UnsignedInteger> Deprecable for ShortintCompressedBootstrappingKey<InputScalar> {
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

impl Upgrade<ShortintCompressedBootstrappingKeyV2> for ShortintCompressedBootstrappingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<ShortintCompressedBootstrappingKeyV2, Self::Error> {
        Ok(match self {
            Self::Classic(seeded_lwe_bootstrap_key) => {
                ShortintCompressedBootstrappingKeyV2::Classic {
                    bsk: seeded_lwe_bootstrap_key,
                    modulus_switch_noise_reduction_key: None,
                }
            }
            Self::MultiBit {
                seeded_bsk,
                deterministic_execution,
            } => ShortintCompressedBootstrappingKeyV2::MultiBit {
                seeded_bsk,
                deterministic_execution,
            },
        })
    }
}

#[derive(Version)]
pub enum ShortintCompressedBootstrappingKeyV2 {
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u64>,
        modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey<u64>>,
    },
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl<InputScalar: UnsignedInteger> Upgrade<ShortintCompressedBootstrappingKey<InputScalar>>
    for ShortintCompressedBootstrappingKeyV2
{
    type Error = crate::Error;

    fn upgrade(self) -> Result<ShortintCompressedBootstrappingKey<InputScalar>, Self::Error> {
        Ok(match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let modulus_switch_noise_reduction_key = modulus_switch_noise_reduction_key
                    .map(|key| {
                        (&key as &dyn Any)
                            .downcast_ref::<CompressedModulusSwitchNoiseReductionKey<InputScalar>>()
                            .ok_or_else(|| {
                                crate::Error::new(format!(
                                    "Expected u64 as InputScalar while upgrading \
                                    ShortintCompressedBootstrappingKey, got {}",
                                    std::any::type_name::<InputScalar>(),
                                ))
                            })
                            .cloned()
                    })
                    .transpose()?;

                ShortintCompressedBootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
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
pub enum ShortintCompressedBootstrappingKeyVersions<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    V0(Deprecated<ShortintCompressedBootstrappingKey<InputScalar>>),
    V1(ShortintCompressedBootstrappingKeyV1),
    V2(ShortintCompressedBootstrappingKeyV2),
    V3(ShortintCompressedBootstrappingKey<InputScalar>),
}

impl Deprecable for CompressedServerKey {
    const TYPE_NAME: &'static str = "CompressedServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct CompressedServerKeyV2 {
    pub key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintCompressedBootstrappingKey<u64>,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

impl Upgrade<CompressedServerKey> for CompressedServerKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedServerKey, Self::Error> {
        let Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus: _, // Ciphertext modulus is on the compressed bootstrapping_key
            pbs_order,
        } = self;

        let compressed_ap_server_key = CompressedAtomicPatternServerKey::Standard(
            CompressedStandardAtomicPatternServerKey::from_raw_parts(
                key_switching_key,
                bootstrapping_key,
                pbs_order,
            ),
        );

        Ok(CompressedServerKey {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedServerKeyVersions {
    V0(Deprecated<CompressedServerKey>),
    V1(Deprecated<CompressedServerKey>),
    V2(CompressedServerKeyV2),
    V3(CompressedServerKey),
}
