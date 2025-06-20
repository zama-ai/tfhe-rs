use std::convert::Infallible;

use crate::core_crypto::prelude::*;
use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
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

impl Upgrade<NoiseSquashingKey> for NoiseSquashingKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<NoiseSquashingKey, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        Ok(NoiseSquashingKey {
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

#[derive(VersionsDispatch)]
pub enum NoiseSquashingKeyVersions {
    V0(NoiseSquashingKeyV0),
    V1(NoiseSquashingKey),
}

#[derive(Version)]
pub struct CompressedNoiseSquashingKeyV0 {
    bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
    modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey<u64>>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<CompressedNoiseSquashingKey> for CompressedNoiseSquashingKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<CompressedNoiseSquashingKey, Self::Error> {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        Ok(CompressedNoiseSquashingKey {
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

#[derive(VersionsDispatch)]
pub enum CompressedNoiseSquashingKeyVersions {
    V0(CompressedNoiseSquashingKeyV0),
    V1(CompressedNoiseSquashingKey),
}
