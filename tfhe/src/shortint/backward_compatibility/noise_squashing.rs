use std::convert::Infallible;

use crate::core_crypto::prelude::*;
use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, CompressedShortint128BootstrappingKey, NoiseSquashingKey,
    NoiseSquashingPrivateKey, Shortint128BootstrappingKey,
};
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey,
};
use crate::shortint::{CarryModulus, MessageModulus};
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(VersionsDispatch)]
pub enum NoiseSquashingPrivateKeyVersions {
    V0(NoiseSquashingPrivateKey),
}

#[derive(Version)]
pub struct NoiseSquashingKeyV0 {
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    modulus_switch_noise_reduction_key: Option<ModulusSwitchNoiseReductionKey<u64>>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<NoiseSquashingKeyV1> for NoiseSquashingKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<NoiseSquashingKeyV1, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        Ok(NoiseSquashingKeyV1 {
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
pub struct NoiseSquashingKeyV1 {
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<u64>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<NoiseSquashingKey> for NoiseSquashingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<NoiseSquashingKey, Self::Error> {
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

        Ok(NoiseSquashingKey::from_raw_parts(
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingKeyVersions {
    V0(NoiseSquashingKeyV0),
    V1(NoiseSquashingKeyV1),
    V2(NoiseSquashingKey),
}

#[derive(VersionsDispatch)]
pub enum Shortint128BootstrappingKeyVersions {
    V0(Shortint128BootstrappingKey),
}

#[derive(VersionsDispatch)]
pub enum CompressedShortint128BootstrappingKeyVersions {
    V0(CompressedShortint128BootstrappingKey),
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

impl Upgrade<CompressedNoiseSquashingKey> for CompressedNoiseSquashingKeyV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedNoiseSquashingKey, Self::Error> {
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

        Ok(CompressedNoiseSquashingKey::from_raw_parts(
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingKeyVersions {
    V0(CompressedNoiseSquashingKeyV0),
    V1(CompressedNoiseSquashingKeyV1),
    V2(CompressedNoiseSquashingKey),
}
