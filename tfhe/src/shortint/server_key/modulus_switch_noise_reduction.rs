use super::{PBSConformanceParameters, PbsTypeConformanceParameters};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{CompressionSeed, DynamicDistribution};
use crate::core_crypto::commons::parameters::{
    LweDimension, NoiseEstimationMeasureBound, PlaintextCount, RSigmaFactor,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use crate::core_crypto::prelude::CiphertextModulusLog;
use crate::shortint::backward_compatibility::server_key::modulus_switch_noise_reduction::*;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::ModulusSwitchNoiseReductionParams;
use crate::shortint::CiphertextModulus;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Copy, Clone)]
pub struct ModulusSwitchNoiseReductionKeyConformanceParameters {
    pub modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
    pub lwe_dimension: LweDimension,
}

impl TryFrom<&PBSConformanceParameters> for ModulusSwitchNoiseReductionKeyConformanceParameters {
    type Error = ();

    fn try_from(value: &PBSConformanceParameters) -> Result<Self, ()> {
        match &value.pbs_type {
            PbsTypeConformanceParameters::Classic {
                modulus_switch_noise_reduction,
            } => modulus_switch_noise_reduction.map_or(Err(()), |modulus_switch_noise_reduction| {
                Ok(Self {
                    modulus_switch_noise_reduction_params: modulus_switch_noise_reduction,
                    lwe_dimension: value.in_lwe_dimension,
                })
            }),
            PbsTypeConformanceParameters::MultiBit { .. } => Err(()),
        }
    }
}

/// Before applying a modulus switch to a ciphertext, it's possible to modify it (but not the value
/// it encrypts) in a way that decreases the noise added by the subsequent modulus switch.
///
/// A [ModulusSwitchNoiseReductionKey] is needed to perform this modification.
/// [improve_modulus_switch_noise](ModulusSwitchNoiseReductionKey::improve_modulus_switch_noise)
/// method can then be called on the target ciphertext.
///
/// The lower level primitive is
/// [improve_lwe_ciphertext_modulus_switch_noise_for_binary_key](crate::core_crypto::algorithms::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ModulusSwitchNoiseReductionKeyVersions)]
pub struct ModulusSwitchNoiseReductionKey {
    pub modulus_switch_zeros: LweCiphertextListOwned<u64>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
}

impl ParameterSetConformant for ModulusSwitchNoiseReductionKey {
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
        } = self;

        *ms_bound == parameter_set.modulus_switch_noise_reduction_params.ms_bound
            && *ms_r_sigma_factor
                == parameter_set
                    .modulus_switch_noise_reduction_params
                    .ms_r_sigma_factor
            && modulus_switch_zeros.entity_count()
                == parameter_set
                    .modulus_switch_noise_reduction_params
                    .modulus_switch_zeros_count
                    .0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == parameter_set.lwe_dimension
    }
}

impl ModulusSwitchNoiseReductionKey {
    pub fn improve_modulus_switch_noise<Cont>(
        &self,
        input: &mut LweCiphertext<Cont>,
        log_modulus: CiphertextModulusLog,
    ) where
        Cont: ContainerMut<Element = u64>,
    {
        improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
            input,
            &self.modulus_switch_zeros,
            self.ms_r_sigma_factor,
            self.ms_bound,
            log_modulus,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedModulusSwitchNoiseReductionKeyVersions)]
pub struct CompressedModulusSwitchNoiseReductionKey {
    pub modulus_switch_zeros: SeededLweCiphertextListOwned<u64>,
    pub ms_bound: NoiseEstimationMeasureBound,
    pub ms_r_sigma_factor: RSigmaFactor,
}

impl ParameterSetConformant for CompressedModulusSwitchNoiseReductionKey {
    type ParameterSet = ModulusSwitchNoiseReductionKeyConformanceParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
        } = self;

        *ms_bound == parameter_set.modulus_switch_noise_reduction_params.ms_bound
            && *ms_r_sigma_factor
                == parameter_set
                    .modulus_switch_noise_reduction_params
                    .ms_r_sigma_factor
            && modulus_switch_zeros.entity_count()
                == parameter_set
                    .modulus_switch_noise_reduction_params
                    .modulus_switch_zeros_count
                    .0
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == parameter_set.lwe_dimension
    }
}

impl ModulusSwitchNoiseReductionKey {
    pub fn new<KeyCont: Container<Element = u64> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CiphertextModulus,
        lwe_noise_distribution: DynamicDistribution<u64>,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros =
            LweCiphertextList::new(0, lwe_size, count, ciphertext_modulus);

        let plaintext_list = PlaintextList::new(0, PlaintextCount(count.0));

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
        }
    }
}

impl CompressedModulusSwitchNoiseReductionKey {
    pub fn new<KeyCont: Container<Element = u64> + Sync>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        engine: &mut ShortintEngine,
        ciphertext_modulus: CiphertextModulus,
        lwe_noise_distribution: DynamicDistribution<u64>,
        compression_seed: CompressionSeed,
    ) -> Self {
        let ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: count,
            ms_bound,
            ms_r_sigma_factor,
        } = modulus_switch_noise_reduction_params;

        let lwe_size = secret_key.lwe_dimension().to_lwe_size();

        let mut modulus_switch_zeros =
            SeededLweCiphertextList::new(0, lwe_size, count, compression_seed, ciphertext_modulus);

        let plaintext_list = PlaintextList::new(0, PlaintextCount(count.0));

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        par_encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            &mut engine.encryption_generator,
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
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
        }
    }

    pub fn decompress(&self) -> ModulusSwitchNoiseReductionKey {
        ModulusSwitchNoiseReductionKey {
            modulus_switch_zeros: self
                .modulus_switch_zeros
                .as_view()
                .decompress_into_lwe_ciphertext_list(),
            ms_bound: self.ms_bound,
            ms_r_sigma_factor: self.ms_r_sigma_factor,
        }
    }
}
