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
    Upgrade<SerializableShortintBootstrappingKeyV1<InputScalar, C>>
    for SerializableShortintBootstrappingKeyV0<C>
where
    InputScalar: UnsignedInteger,
{
    type Error = Infallible;

    fn upgrade(
        self,
    ) -> Result<SerializableShortintBootstrappingKeyV1<InputScalar, C>, Self::Error> {
        Ok(match self {
            Self::Classic(bsk) => SerializableShortintBootstrappingKeyV1::Classic {
                bsk,
                modulus_switch_noise_reduction_key: None,
            },
            Self::MultiBit {
                fourier_bsk,
                deterministic_execution,
            } => SerializableShortintBootstrappingKeyV1::MultiBit {
                fourier_bsk,
                deterministic_execution,
            },
        })
    }
}

#[derive(Version)]
pub enum SerializableShortintBootstrappingKeyV1<InputScalar, C: Container<Element = tfhe_fft::c64>>
where
    InputScalar: UnsignedInteger,
{
    Classic {
        bsk: FourierLweBootstrapKey<C>,
        modulus_switch_noise_reduction_key: Option<ModulusSwitchNoiseReductionKey<InputScalar>>,
    },
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl<InputScalar, C: Container<Element = tfhe_fft::c64>>
    Upgrade<SerializableShortintBootstrappingKey<InputScalar, C>>
    for SerializableShortintBootstrappingKeyV1<InputScalar, C>
where
    InputScalar: UnsignedInteger,
{
    type Error = Infallible;

    fn upgrade(self) -> Result<SerializableShortintBootstrappingKey<InputScalar, C>, Self::Error> {
        Ok(match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => SerializableShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_key.map_or(
                    ModulusSwitchConfiguration::Standard,
                    |modulus_switch_noise_reduction_key| {
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        )
                    },
                ),
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
    // Here a generic `InputScalar` has been added but it does not requires a new version since it
    // is only added through the `ModulusSwitchNoiseReductionKey`, which handles the
    // upgrade itself.
    V1(SerializableShortintBootstrappingKeyV1<InputScalar, C>),
    V2(SerializableShortintBootstrappingKey<InputScalar, C>),
}

impl Deprecable for ServerKey {
    const TYPE_NAME: &'static str = "ServerKey";
    const MIN_SUPPORTED_APP_VERSION: &'static str = "TFHE-rs v0.10";
}

#[derive(Version)]
pub struct GenericServerKeyV1 {
    key_switching_key: LweKeyswitchKeyOwned<u64>,
    bootstrapping_key: ShortintBootstrappingKey<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    max_degree: MaxDegree,
    max_noise_level: MaxNoiseLevel,
    ciphertext_modulus: CiphertextModulus,
    pbs_order: PBSOrder,
}

impl<AP: 'static> Upgrade<GenericServerKey<AP>> for GenericServerKeyV1 {
    type Error = Error;

    fn upgrade(self) -> Result<GenericServerKey<AP>, Self::Error> {
        let std_ap = StandardAtomicPatternServerKey::from_raw_parts(
            self.key_switching_key,
            self.bootstrapping_key,
            self.pbs_order,
        );

        if TypeId::of::<AP>() == TypeId::of::<AtomicPatternServerKey>() {
            let ap = AtomicPatternServerKey::Standard(std_ap);
            let sk: Box<dyn Any + 'static> = Box::new(ServerKey::from_raw_parts(
                ap,
                self.message_modulus,
                self.carry_modulus,
                self.max_degree,
                self.max_noise_level,
            ));
            Ok(*sk.downcast::<GenericServerKey<AP>>().unwrap()) // We know from the TypeId that
                                                                // AP is of the right type so we
                                                                // can unwrap
        } else if TypeId::of::<AP>() == TypeId::of::<StandardAtomicPatternServerKey>() {
            let sk: Box<dyn Any + 'static> = Box::new(StandardServerKey::from_raw_parts(
                std_ap,
                self.message_modulus,
                self.carry_modulus,
                self.max_degree,
                self.max_noise_level,
            ));
            Ok(*sk.downcast::<GenericServerKey<AP>>().unwrap()) // We know from the TypeId that
                                                                // AP is of the right type so we
                                                                // can unwrap
        } else {
            Err(Error::new(
                "ServerKey from TFHE-rs 1.0 and before can only be deserialized to the standard \
Atomic Pattern"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum GenericServerKeyVersions<AP> {
    V0(Deprecated<ServerKey>),
    V1(GenericServerKeyV1),
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

impl<InputScalar: UnsignedInteger> Upgrade<ShortintCompressedBootstrappingKeyV2<InputScalar>>
    for ShortintCompressedBootstrappingKeyV1
{
    type Error = Infallible;

    fn upgrade(self) -> Result<ShortintCompressedBootstrappingKeyV2<InputScalar>, Self::Error> {
        Ok(match self {
            Self::Classic(bsk) => ShortintCompressedBootstrappingKeyV2::Classic {
                bsk,
                modulus_switch_noise_reduction_key: None,
            },
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
pub enum ShortintCompressedBootstrappingKeyV2<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u64>,
        modulus_switch_noise_reduction_key:
            Option<CompressedModulusSwitchNoiseReductionKey<InputScalar>>,
    },
    MultiBit {
        seeded_bsk: SeededLweMultiBitBootstrapKeyOwned<u64>,
        deterministic_execution: bool,
    },
}

impl<InputScalar: UnsignedInteger> Upgrade<ShortintCompressedBootstrappingKey<InputScalar>>
    for ShortintCompressedBootstrappingKeyV2<InputScalar>
{
    type Error = Infallible;

    fn upgrade(self) -> Result<ShortintCompressedBootstrappingKey<InputScalar>, Self::Error> {
        Ok(match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => ShortintCompressedBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_key.map_or(
                    CompressedModulusSwitchConfiguration::Standard,
                    |modulus_switch_noise_reduction_key| {
                        CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        )
                    },
                ),
            },
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
    // Here a generic `InputScalar` has been added but it does not requires a new version since it
    // is only added through the `CompressedModulusSwitchNoiseReductionKey`, which handles the
    // upgrade itself.
    V2(ShortintCompressedBootstrappingKeyV2<InputScalar>),
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
