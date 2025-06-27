use std::any::Any;

use crate::core_crypto::prelude::UnsignedInteger;
use crate::shortint::parameters::{NoiseEstimationMeasureBound, RSigmaFactor, Variance};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, CompressedModulusSwitchNoiseReductionKey,
    ModulusSwitchConfiguration, ModulusSwitchNoiseReductionKey,
};
use crate::Error;
use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use super::{LweCiphertextListOwned, SeededLweCiphertextListOwned};

#[derive(Version)]
pub struct ModulusSwitchNoiseReductionKeyV0 {
    modulus_switch_zeros: LweCiphertextListOwned<u64>,
    ms_bound: NoiseEstimationMeasureBound,
    ms_r_sigma_factor: RSigmaFactor,
    ms_input_variance: Variance,
}

impl<InputScalar> Upgrade<ModulusSwitchNoiseReductionKey<InputScalar>>
    for ModulusSwitchNoiseReductionKeyV0
where
    InputScalar: UnsignedInteger,
{
    type Error = Error;

    fn upgrade(self) -> Result<ModulusSwitchNoiseReductionKey<InputScalar>, Self::Error> {
        let modulus_switch_zeros: Box<dyn Any> = Box::new(self.modulus_switch_zeros);

        // Keys from previous versions where only stored as u64, we check if the destination
        // key is also u64 or we return an error
        Ok(ModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: *modulus_switch_zeros
                .downcast::<LweCiphertextListOwned<InputScalar>>()
                .map_err(|_| {
                    Error::new(format!(
                        "Expected u64 as InputScalar while upgrading \
                            ModulusSwitchNoiseReductionKey, got {}",
                        std::any::type_name::<InputScalar>(),
                    ))
                })?,
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
            ms_input_variance: self.ms_input_variance,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum ModulusSwitchNoiseReductionKeyVersions<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    V0(ModulusSwitchNoiseReductionKeyV0),
    V1(ModulusSwitchNoiseReductionKey<InputScalar>),
}

#[derive(Version)]
pub struct CompressedModulusSwitchNoiseReductionKeyV0 {
    pub modulus_switch_zeros: SeededLweCiphertextListOwned<u64>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}

impl<InputScalar> Upgrade<CompressedModulusSwitchNoiseReductionKey<InputScalar>>
    for CompressedModulusSwitchNoiseReductionKeyV0
where
    InputScalar: UnsignedInteger,
{
    type Error = Error;

    fn upgrade(self) -> Result<CompressedModulusSwitchNoiseReductionKey<InputScalar>, Self::Error> {
        let modulus_switch_zeros: Box<dyn Any> = Box::new(self.modulus_switch_zeros);

        // Keys from previous versions where only stored as u64, we check if the destination
        // key is also u64 or we return an error
        Ok(CompressedModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: *modulus_switch_zeros
                .downcast::<SeededLweCiphertextListOwned<InputScalar>>()
                .map_err(|_| {
                    Error::new(format!(
                        "Expected u64 as InputScalar while upgrading \
                        CompressedModulusSwitchNoiseReductionKey, got {}",
                        std::any::type_name::<InputScalar>(),
                    ))
                })?,
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
            ms_input_variance: self.ms_input_variance,
        })
    }
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchNoiseReductionKeyVersions<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    V0(CompressedModulusSwitchNoiseReductionKeyV0),
    V1(CompressedModulusSwitchNoiseReductionKey<InputScalar>),
}

#[derive(VersionsDispatch)]
pub enum CompressedModulusSwitchConfigurationVersions<Scalar: UnsignedInteger> {
    V0(CompressedModulusSwitchConfiguration<Scalar>),
}

#[derive(VersionsDispatch)]
pub enum ModulusSwitchConfigurationVersions<Scalar: UnsignedInteger> {
    V0(ModulusSwitchConfiguration<Scalar>),
}
