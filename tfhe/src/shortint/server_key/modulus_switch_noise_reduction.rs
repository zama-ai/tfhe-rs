use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{CompressionSeed, DynamicDistribution};
use crate::core_crypto::commons::parameters::{LweCiphertextCount, LweDimension, PlaintextCount};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::shortint::CiphertextModulus;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::NotVersioned;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct ModulusSwitchNoiseReductionParams {
    pub modulus_switch_zeros_count: usize,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
}

#[derive(Copy, Clone)]
pub struct ModulusSwitchNoiseReductionKeyConformanceParameters {
    pub modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
    pub lwe_dimension: LweDimension,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct ModulusSwitchNoiseReductionKey {
    pub modulus_switch_zeros: LweCiphertextListOwned<u64>,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
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
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == parameter_set.lwe_dimension
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)]
pub struct CompressedModulusSwitchNoiseReductionKey {
    pub modulus_switch_zeros: SeededLweCiphertextListOwned<u64>,
    pub ms_bound: f64,
    pub ms_r_sigma_factor: f64,
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
            && modulus_switch_zeros.lwe_size().to_lwe_dimension() == parameter_set.lwe_dimension
    }
}

impl ModulusSwitchNoiseReductionKey {
    pub fn new<G: ByteRandomGenerator, KeyCont: Container<Element = u64>>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        encryption_generator: &mut EncryptionRandomGenerator<G>,
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
            LweCiphertextList::new(0, lwe_size, LweCiphertextCount(count), ciphertext_modulus);

        let plaintext_list = PlaintextList::new(0, PlaintextCount(count));

        encrypt_lwe_ciphertext_list(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            encryption_generator,
        );

        Self {
            modulus_switch_zeros,
            ms_bound,
            ms_r_sigma_factor,
        }
    }
}

impl CompressedModulusSwitchNoiseReductionKey {
    pub fn new<G: ByteRandomGenerator, KeyCont: Container<Element = u64>>(
        modulus_switch_noise_reduction_params: ModulusSwitchNoiseReductionParams,
        secret_key: &LweSecretKey<KeyCont>,
        encryption_generator: &mut EncryptionRandomGenerator<G>,
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

        let mut modulus_switch_zeros = SeededLweCiphertextList::new(
            0,
            lwe_size,
            LweCiphertextCount(count),
            compression_seed,
            ciphertext_modulus,
        );

        let plaintext_list = PlaintextList::new(0, PlaintextCount(count));

        encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
            secret_key,
            &mut modulus_switch_zeros,
            &plaintext_list,
            lwe_noise_distribution,
            encryption_generator,
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
