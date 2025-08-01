use crate::core_crypto::prelude::*;
use crate::shortint::parameters::noise_squashing::{
    NoiseSquashingClassicParameters, NoiseSquashingCompressionParameters,
    NoiseSquashingMultiBitParameters, NoiseSquashingParameters,
};
use crate::shortint::parameters::{
    CoreCiphertextModulus, ModulusSwitchNoiseReductionParams, ModulusSwitchType,
};
use crate::shortint::{CarryModulus, MessageModulus};
use std::convert::Infallible;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

#[derive(Version)]
pub struct NoiseSquashingParametersV0 {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub modulus_switch_noise_reduction_params: Option<ModulusSwitchNoiseReductionParams>,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<NoiseSquashingParametersV1> for NoiseSquashingParametersV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<NoiseSquashingParametersV1, Self::Error> {
        let Self {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            modulus_switch_noise_reduction_params,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = self;

        Ok(NoiseSquashingParametersV1 {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            modulus_switch_noise_reduction_params: modulus_switch_noise_reduction_params.map_or(
                ModulusSwitchType::Standard,
                |modulus_switch_noise_reduction_params| {
                    ModulusSwitchType::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_params,
                    )
                },
            ),
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        })
    }
}

#[derive(Version)]
pub struct NoiseSquashingParametersV1 {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_noise_distribution: DynamicDistribution<u128>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl Upgrade<NoiseSquashingParameters> for NoiseSquashingParametersV1 {
    type Error = Infallible;

    fn upgrade(self) -> Result<NoiseSquashingParameters, Self::Error> {
        let Self {
            glwe_dimension,
            polynomial_size,
            glwe_noise_distribution,
            decomp_base_log,
            decomp_level_count,
            modulus_switch_noise_reduction_params,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
        } = self;

        Ok(NoiseSquashingParameters::Classic(
            NoiseSquashingClassicParameters {
                glwe_dimension,
                polynomial_size,
                glwe_noise_distribution,
                decomp_base_log,
                decomp_level_count,
                modulus_switch_noise_reduction_params,
                message_modulus,
                carry_modulus,
                ciphertext_modulus,
            },
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingParametersVersions {
    V0(NoiseSquashingParametersV0),
    V1(NoiseSquashingParametersV1),
    V2(NoiseSquashingParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingClassicParametersVersions {
    V0(NoiseSquashingClassicParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingMultiBitParametersVersions {
    V0(NoiseSquashingMultiBitParameters),
}

#[derive(VersionsDispatch)]
pub enum NoiseSquashingCompressionParametersVersions {
    V0(NoiseSquashingCompressionParameters),
}
