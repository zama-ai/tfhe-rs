use super::{PBSConformanceParams, PbsTypeConformanceParams};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{CompressionSeed, DynamicDistribution, Uniform};
use crate::core_crypto::commons::parameters::{
    LweDimension, NoiseEstimationMeasureBound, PlaintextCount, RSigmaFactor,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use crate::core_crypto::prelude::{
    CiphertextModulus as CoreCiphertextModulus, CiphertextModulusLog, Variance,
};
use crate::shortint::backward_compatibility::server_key::modulus_switch_noise_reduction::*;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Copy, Clone)]
pub struct ModulusSwitchNoiseReductionKeyConformanceParams {
    pub modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
    pub lwe_dimension: LweDimension,
}

impl TryFrom<&PBSConformanceParams> for ModulusSwitchNoiseReductionKeyConformanceParams {
    type Error = ();

    fn try_from(value: &PBSConformanceParams) -> Result<Self, ()> {
        match &value.pbs_type {
            PbsTypeConformanceParams::Classic {
                modulus_switch_noise_reduction,
            } => modulus_switch_noise_reduction.map_or(Err(()), |modulus_switch_noise_reduction| {
                Ok(Self {
                    modulus_switch_noise_reduction_params: modulus_switch_noise_reduction,
                    lwe_dimension: value.in_lwe_dimension,
                })
            }),
            PbsTypeConformanceParams::MultiBit { .. } => Err(()),
        }
    }
}

/// Using a [ModulusSwitchNoiseReductionKey], it's possible do apply a modulus switch which adds
/// less noise by calling the
/// [switch_modulus](ModulusSwitchNoiseReductionKey::improve_noise_and_modulus_switch) method on the
/// target ciphertext.
///
/// The lower level primitive is
/// [improve_lwe_ciphertext_modulus_switch_noise_for_binary_key](crate::core_crypto::algorithms::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchNoiseReductionKeyVersions)]
pub struct ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub modulus_switch_zeros: LweCiphertextListOwned<InputScalar>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}

impl<InputScalar> ParameterSetConformant for ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = self;

        let ModulusSwitchNoiseReductionKeyConformanceParams {
            modulus_switch_noise_reduction_params,
            lwe_dimension,
        } = parameter_set;

        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: param_modulus_switch_zeros_count,
            ms_bound: param_ms_bound,
            ms_r_sigma_factor: param_ms_r_sigma_factor,
            ms_input_variance: param_ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        ms_bound == param_ms_bound
            && ms_r_sigma_factor == param_ms_r_sigma_factor
            && ms_input_variance == param_ms_input_variance
            && modulus_switch_zeros.entity_count() == param_modulus_switch_zeros_count.0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == *lwe_dimension
    }
}

impl<InputScalar> ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    fn improve_modulus_switch_noise<Cont>(
        &self,
        input: &mut LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) where
        Cont: ContainerMut<Element = InputScalar>,
    {
        improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
            input,
            &self.modulus_switch_zeros,
            self.ms_r_sigma_factor,
            self.ms_bound,
            self.ms_input_variance,
            log_modulus,
        );
    }

    pub fn improve_noise_and_modulus_switch<Cont, SwitchedScalar>(
        &self,
        input: &LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) -> LazyStandardModulusSwitchedLweCiphertext<InputScalar, SwitchedScalar, Vec<InputScalar>>
    where
        InputScalar: CastInto<SwitchedScalar>,
        SwitchedScalar: UnsignedInteger,
        Cont: Container<Element = InputScalar>,
    {
        let mut input: LweCiphertext<Vec<InputScalar>> =
            LweCiphertext::from_container(input.as_ref().to_owned(), input.ciphertext_modulus());

        self.improve_modulus_switch_noise(&mut input, log_modulus);

        lwe_ciphertext_modulus_switch(input, log_modulus)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchNoiseReductionKeyVersions)]
pub struct CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub modulus_switch_zeros: SeededLweCiphertextListOwned<InputScalar>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
    pub ms_input_variance: Variance,
}

impl<InputScalar> ParameterSetConformant for CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = self;

        let ModulusSwitchNoiseReductionKeyConformanceParams {
            modulus_switch_noise_reduction_params,
            lwe_dimension,
        } = parameter_set;

        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: param_modulus_switch_zeros_count,
            ms_bound: param_ms_bound,
            ms_r_sigma_factor: param_ms_r_sigma_factor,
            ms_input_variance: param_ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        ms_bound == param_ms_bound
            && ms_r_sigma_factor == param_ms_r_sigma_factor
            && ms_input_variance == param_ms_input_variance
            && modulus_switch_zeros.entity_count() == param_modulus_switch_zeros_count.0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == *lwe_dimension
    }
}

impl<InputScalar> ModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: Encryptable<Uniform, DynamicDistribution<InputScalar>>,
{
    pub fn new<KeyCont: Container<Element = InputScalar> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CoreCiphertextModulus<InputScalar>,
        lwe_noise_distribution: DynamicDistribution<InputScalar>,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros =
            LweCiphertextList::new(InputScalar::ZERO, lwe_size, count, ciphertext_modulus);

        let plaintext_list = PlaintextList::new(InputScalar::ZERO, PlaintextCount(count.0));

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        par_encrypt_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.encryption_generator,
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        encrypt_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.encryption_generator,
        );

        Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        }
    }
}

impl<InputScalar> CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: Encryptable<Uniform, DynamicDistribution<InputScalar>>,
{
    pub fn new<KeyCont: Container<Element = InputScalar> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CoreCiphertextModulus<InputScalar>,
        lwe_noise_distribution: DynamicDistribution<InputScalar>,
        compression_seed: CompressionSeed,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros = SeededLweCiphertextList::new(
            InputScalar::ZERO,
            lwe_size,
            count,
            compression_seed,
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(InputScalar::ZERO, PlaintextCount(count.0));

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        par_encrypt_seeded_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.seeder,
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        encrypt_seeded_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.seeder,
        );

        Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
            ms_input_variance,
        }
    }
}

impl<InputScalar> CompressedModulusSwitchNoiseReductionKey<InputScalar>
where
    InputScalar: UnsignedTorus,
{
    pub fn decompress(&self) -> ModulusSwitchNoiseReductionKey<InputScalar> {
        ModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: self
                .modulus_switch_zeros
                .as_view()
                .decompress_into_lwe_ciphertext_list(),
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
            ms_input_variance: self.ms_input_variance,
        }
    }
}
