use std::any::{Any, TypeId};
use std::convert::Infallible;

use crate::core_crypto::prelude::fft128_lwe_multi_bit_bootstrap_key::Fourier128LweMultiBitBootstrapKeyOwned;
use crate::core_crypto::prelude::*;

use crate::shortint::noise_squashing::atomic_pattern::compressed::ks32::CompressedKS32AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::compressed::standard::CompressedStandardAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::ks32::KS32AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::standard::StandardAtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::atomic_pattern::AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, CompressedShortint128BootstrappingKey, GenericNoiseSquashingKey,
    NoiseSquashingKey, NoiseSquashingPrivateKey, Shortint128BootstrappingKey,
    StandardNoiseSquashingKey,
};
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey,
};
use crate::shortint::{CarryModulus, MessageModulus};
use crate::Error;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum NoiseSquashingPrivateKeyVersions {
    V0(NoiseSquashingPrivateKey),
}

#[derive(Version)]
pub struct GenericNoiseSquashingKeyV0 {
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    modulus_switch_noise_reduction_key: Option<ModulusSwitchNoiseReductionKey<u64>>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<GenericNoiseSquashingKeyV1> for GenericNoiseSquashingKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<GenericNoiseSquashingKeyV1, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        Ok(GenericNoiseSquashingKeyV1 {
            bootstrapping_key,
            modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_key.map_or(
                ModulusSwitchConfiguration::Standard,
                |modulus_switch_noise_reduction_key| {
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    )
                },
            ),
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct GenericNoiseSquashingKeyV1 {
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<GenericNoiseSquashingKeyV2> for GenericNoiseSquashingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<GenericNoiseSquashingKeyV2, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let bootstrapping_key = Shortint128BootstrappingKey::Classic {
            bsk: bootstrapping_key,
            modulus_switch_noise_reduction_key,
        };

        Ok(GenericNoiseSquashingKeyV2 {
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct GenericNoiseSquashingKeyV2 {
    bootstrapping_key: Shortint128BootstrappingKey<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl<AP: 'static> Upgrade<GenericNoiseSquashingKey<AP>> for GenericNoiseSquashingKeyV2 {
    type Error = Error;

    fn upgrade(self) -> Result<GenericNoiseSquashingKey<AP>, Self::Error> {
        let std_ap = StandardAtomicPatternNoiseSquashingKey::from_raw_parts(self.bootstrapping_key);

        if TypeId::of::<AP>() == TypeId::of::<AtomicPatternNoiseSquashingKey>() {
            let ap = AtomicPatternNoiseSquashingKey::Standard(std_ap);
            let sk: Box<dyn Any + 'static> = Box::new(NoiseSquashingKey::from_raw_parts(
                ap,
                self.message_modulus,
                self.carry_modulus,
                self.output_ciphertext_modulus,
            ));
            // We know from the TypeId that AP is of the right type so we can unwrap
            Ok(*sk.downcast::<GenericNoiseSquashingKey<AP>>().unwrap())
        } else if TypeId::of::<AP>() == TypeId::of::<StandardAtomicPatternNoiseSquashingKey>() {
            let sk: Box<dyn Any + 'static> = Box::new(StandardNoiseSquashingKey::from_raw_parts(
                std_ap,
                self.message_modulus,
                self.carry_modulus,
                self.output_ciphertext_modulus,
            ));
            // We know from the TypeId that AP is of the right type so we can unwrap
            Ok(*sk.downcast::<GenericNoiseSquashingKey<AP>>().unwrap())
        } else {
            Err(Error::new(
                "NoiseSquashingKey from TFHE-rs 1.3 and before can only be deserialized to the standard \
Atomic Pattern"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum GenericNoiseSquashingKeyVersions<AP> {
    V0(GenericNoiseSquashingKeyV0),
    V1(GenericNoiseSquashingKeyV1),
    V2(GenericNoiseSquashingKeyV2),
    V3(GenericNoiseSquashingKey<AP>),
}

#[derive(Version)]
pub enum Shortint128BootstrappingKeyV0 {
    Classic {
        bsk: Fourier128LweBootstrapKeyOwned,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<u64>,
    },
    MultiBit {
        bsk: Fourier128LweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<Scalar: UnsignedInteger> Upgrade<Shortint128BootstrappingKey<Scalar>>
    for Shortint128BootstrappingKeyV0
{
    type Error = Error;

    fn upgrade(self) -> Result<Shortint128BootstrappingKey<Scalar>, Self::Error> {
        if TypeId::of::<Scalar>() == TypeId::of::<u64>() {
            Ok(match self {
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                } => {
                    let noise_reduction_key =
                        Box::new(modulus_switch_noise_reduction_key) as Box<dyn Any>;

                    Shortint128BootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: *noise_reduction_key
                            .downcast::<ModulusSwitchConfiguration<Scalar>>()
                            .unwrap(),
                    }
                }
                Self::MultiBit {
                    bsk,
                    thread_count,
                    deterministic_execution,
                } => Shortint128BootstrappingKey::MultiBit {
                    bsk,
                    thread_count,
                    deterministic_execution,
                },
            })
        } else {
            Err(Error::new(
                "Shortint128BootstrappingKey from TFHE-rs 1.3 and before only support u64 drift\
 mitigation key coefficients"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum Shortint128BootstrappingKeyVersions<Scalar>
where
    Scalar: UnsignedInteger,
{
    V0(Shortint128BootstrappingKeyV0),
    V1(Shortint128BootstrappingKey<Scalar>),
}

#[derive(Version)]
pub enum CompressedShortint128BootstrappingKeyV0 {
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u128>,
        modulus_switch_noise_reduction_key: CompressedModulusSwitchConfiguration<u64>,
    },
    MultiBit {
        bsk: SeededLweMultiBitBootstrapKeyOwned<u128>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<Scalar: UnsignedInteger> Upgrade<CompressedShortint128BootstrappingKey<Scalar>>
    for CompressedShortint128BootstrappingKeyV0
{
    type Error = Error;

    fn upgrade(self) -> Result<CompressedShortint128BootstrappingKey<Scalar>, Self::Error> {
        if TypeId::of::<Scalar>() == TypeId::of::<u64>() {
            Ok(match self {
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                } => {
                    let noise_reduction_key =
                        Box::new(modulus_switch_noise_reduction_key) as Box<dyn Any>;

                    CompressedShortint128BootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: *noise_reduction_key
                            .downcast::<CompressedModulusSwitchConfiguration<Scalar>>()
                            .unwrap(),
                    }
                }
                Self::MultiBit {
                    bsk,
                    thread_count,
                    deterministic_execution,
                } => CompressedShortint128BootstrappingKey::MultiBit {
                    bsk,
                    thread_count,
                    deterministic_execution,
                },
            })
        } else {
            Err(Error::new(
                "CompressedShortint128BootstrappingKey from TFHE-rs 1.3 and before only support u64 \
drift mitigation key coefficients"
                    .to_string(),
            ))
        }
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedShortint128BootstrappingKeyVersions<Scalar>
where
    Scalar: UnsignedInteger,
{
    V0(CompressedShortint128BootstrappingKeyV0),
    V1(CompressedShortint128BootstrappingKey<Scalar>),
}

#[derive(Version)]
pub struct CompressedNoiseSquashingKeyV0 {
    bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
    modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey<u64>>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<CompressedNoiseSquashingKeyV1> for CompressedNoiseSquashingKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedNoiseSquashingKeyV1, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        Ok(CompressedNoiseSquashingKeyV1 {
            bootstrapping_key,
            modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_key.map_or(
                CompressedModulusSwitchConfiguration::Standard,
                |modulus_switch_noise_reduction_key| {
                    CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    )
                },
            ),
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct CompressedNoiseSquashingKeyV1 {
    bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
    modulus_switch_noise_reduction_key: CompressedModulusSwitchConfiguration<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<CompressedNoiseSquashingKeyV2> for CompressedNoiseSquashingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedNoiseSquashingKeyV2, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let bootstrapping_key = CompressedShortint128BootstrappingKey::Classic {
            bsk: bootstrapping_key,
            modulus_switch_noise_reduction_key,
        };

        Ok(CompressedNoiseSquashingKeyV2 {
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct CompressedNoiseSquashingKeyV2 {
    bootstrapping_key: CompressedShortint128BootstrappingKey<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<CompressedNoiseSquashingKey> for CompressedNoiseSquashingKeyV2 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedNoiseSquashingKey, Self::Error> {
        let std_ap = CompressedStandardAtomicPatternNoiseSquashingKey::from_raw_parts(
            self.bootstrapping_key,
        );

        let atomic_pattern = CompressedAtomicPatternNoiseSquashingKey::Standard(std_ap);

        Ok(CompressedNoiseSquashingKey::from_raw_parts(
            atomic_pattern,
            self.message_modulus,
            self.carry_modulus,
            self.output_ciphertext_modulus,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingKeyVersions {
    V0(CompressedNoiseSquashingKeyV0),
    V1(CompressedNoiseSquashingKeyV1),
    V2(CompressedNoiseSquashingKeyV2),
    V3(CompressedNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum AtomicPatternNoiseSquashingKeyVersions {
    V0(AtomicPatternNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum StandardAtomicPatternNoiseSquashingKeyVersions {
    V0(StandardAtomicPatternNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum KS32AtomicPatternNoiseSquashingKeyVersions {
    V0(KS32AtomicPatternNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedAtomicPatternNoiseSquashingKeyVersions {
    V0(CompressedAtomicPatternNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedStandardAtomicPatternNoiseSquashingKeyVersions {
    V0(CompressedStandardAtomicPatternNoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedKS32AtomicPatternNoiseSquashingKeyVersions {
    V0(CompressedKS32AtomicPatternNoiseSquashingKey),
}
