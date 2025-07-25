use super::{NoiseSquashingKey, NoiseSquashingKeyConformanceParams, NoiseSquashingPrivateKey};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_seeded_lwe_bootstrap_key;
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, SeededLweBootstrapKeyOwned};
use crate::core_crypto::prelude::{
    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key,
    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128,
    Fourier128LweMultiBitBootstrapKey, SeededLweMultiBitBootstrapKeyOwned, ThreadCount,
};
use crate::shortint::backward_compatibility::noise_squashing::{
    CompressedNoiseSquashingKeyVersions, SeededShortint128BootstrappingKeyVersions,
};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::noise_squashing::server_key::Shortint128BootstrappingKey;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, MessageModulus, ModulusSwitchType,
    NoiseSquashingParameters,
};
use crate::shortint::server_key::{
    CompressedModulusSwitchConfiguration, ModulusSwitchNoiseReductionKeyConformanceParams,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(SeededShortint128BootstrappingKeyVersions)]
pub enum SeededShortint128BootstrappingKey {
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

impl SeededShortint128BootstrappingKey {
    fn decompress(&self) -> Shortint128BootstrappingKey {
        match self {
            Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => {
                let (bootstrapping_key, modulus_switch_noise_reduction_key) = {
                    let std_bsk = bsk.as_view().par_decompress_into_lwe_bootstrap_key();

                    let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                        std_bsk.input_lwe_dimension(),
                        std_bsk.glwe_size(),
                        std_bsk.polynomial_size(),
                        std_bsk.decomposition_base_log(),
                        std_bsk.decomposition_level_count(),
                    );

                    par_convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bsk, &mut fbsk);

                    (fbsk, modulus_switch_noise_reduction_key.decompress())
                };

                Shortint128BootstrappingKey::Classic {
                    bsk: bootstrapping_key,
                    modulus_switch_noise_reduction_key,
                }
            }
            Self::MultiBit {
                bsk,
                thread_count,
                deterministic_execution,
            } => {
                let bsk = bsk
                    .as_view()
                    .par_decompress_into_lwe_multi_bit_bootstrap_key();

                let mut fourier_bsk = Fourier128LweMultiBitBootstrapKey::new(
                    bsk.input_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    bsk.decomposition_base_log(),
                    bsk.decomposition_level_count(),
                    bsk.grouping_factor(),
                );

                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128(
                    &bsk,
                    &mut fourier_bsk,
                );

                Shortint128BootstrappingKey::MultiBit {
                    bsk: fourier_bsk,
                    thread_count: *thread_count,
                    deterministic_execution: *deterministic_execution,
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingKeyVersions)]
pub struct CompressedNoiseSquashingKey {
    bootstrapping_key: SeededShortint128BootstrappingKey,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl ClientKey {
    pub fn new_compressed_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> CompressedNoiseSquashingKey {
        let AtomicPatternClientKey::Standard(std_cks) = &self.atomic_pattern else {
            panic!("Only the standard atomic pattern supports noise squashing")
        };

        let pbs_parameters = std_cks.parameters;

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        assert_eq!(
            pbs_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus(),
            "Mismatched MessageModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            pbs_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus()
        );
        assert_eq!(
            pbs_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus(),
            "Mismatched CarryModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            pbs_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus()
        );

        let bootstrapping_key = match noise_squashing_parameters {
            NoiseSquashingParameters::Classic(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let seeded_bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                        &std_cks.lwe_secret_key,
                        noise_squashing_private_key.post_noise_squashing_secret_key(),
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.glwe_noise_distribution,
                        params.ciphertext_modulus,
                        &mut engine.seeder,
                    );

                    let modulus_switch_noise_reduction_key = params
                        .modulus_switch_noise_reduction_params
                        .to_compressed_modulus_switch_configuration(
                            &std_cks.lwe_secret_key,
                            pbs_parameters.ciphertext_modulus(),
                            pbs_parameters.lwe_noise_distribution(),
                            engine,
                        );

                    SeededShortint128BootstrappingKey::Classic {
                        bsk: seeded_bsk,
                        modulus_switch_noise_reduction_key,
                    }
                })
            }
            NoiseSquashingParameters::MultiBit(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let seeded_bsk =
                        par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                            &std_cks.lwe_secret_key,
                            noise_squashing_private_key.post_noise_squashing_secret_key(),
                            params.decomp_base_log,
                            params.decomp_level_count,
                            params.glwe_noise_distribution,
                            params.grouping_factor,
                            params.ciphertext_modulus,
                            &mut engine.seeder,
                        );

                    let thread_count = engine.get_thread_count_for_multi_bit_pbs(
                        std_cks.lwe_secret_key.lwe_dimension(),
                        params.glwe_dimension,
                        params.polynomial_size,
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.grouping_factor,
                    );

                    SeededShortint128BootstrappingKey::MultiBit {
                        bsk: seeded_bsk,
                        thread_count,
                        deterministic_execution: params.deterministic_execution,
                    }
                })
            }
        };

        CompressedNoiseSquashingKey {
            bootstrapping_key,
            output_ciphertext_modulus: noise_squashing_parameters.ciphertext_modulus(),
            message_modulus: noise_squashing_parameters.message_modulus(),
            carry_modulus: noise_squashing_parameters.carry_modulus(),
        }
    }
}

impl CompressedNoiseSquashingKey {
    pub fn new(
        client_key: &ClientKey,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self {
        client_key.new_compressed_noise_squashing_key(noise_squashing_private_key)
    }

    pub fn from_raw_parts(
        bootstrapping_key: SeededShortint128BootstrappingKey,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> Self {
        Self {
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        }
    }

    pub fn decompress(&self) -> NoiseSquashingKey {
        NoiseSquashingKey::from_raw_parts(
            self.bootstrapping_key.decompress(),
            self.message_modulus,
            self.carry_modulus,
            self.output_ciphertext_modulus,
        )
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        self.carry_modulus
    }

    pub fn output_ciphertext_modulus(&self) -> CoreCiphertextModulus<u128> {
        self.output_ciphertext_modulus
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        match (bootstrapping_key, parameter_set) {
            (
                SeededShortint128BootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                NoiseSquashingKeyConformanceParams::Classic {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                    modulus_switch_noise_reduction_params:
                        expected_modulus_switch_noise_reduction_params,
                    message_modulus: expected_message_modulus,
                    carry_modulus: expected_carry_modulus,
                },
            ) => {
                let lwe_dimension = bsk.input_lwe_dimension();

                let modulus_switch_key_ok = match (
                    modulus_switch_noise_reduction_key,
                    expected_modulus_switch_noise_reduction_params,
                ) {
                    (
                        CompressedModulusSwitchConfiguration::Standard,
                        ModulusSwitchType::Standard,
                    ) => true,
                    (
                        CompressedModulusSwitchConfiguration::CenteredMeanNoiseReduction,
                        ModulusSwitchType::CenteredMeanNoiseReduction,
                    ) => true,
                    (
                        CompressedModulusSwitchConfiguration::DriftTechniqueNoiseReduction(key),
                        ModulusSwitchType::DriftTechniqueNoiseReduction(params),
                    ) => {
                        let mod_switch_conformance_params =
                            ModulusSwitchNoiseReductionKeyConformanceParams {
                                modulus_switch_noise_reduction_params: *params,
                                lwe_dimension,
                            };

                        key.is_conformant(&mod_switch_conformance_params)
                    }
                    (_, _) => false,
                };

                modulus_switch_key_ok
                    && bsk.is_conformant(expected_bootstrapping_key_params)
                    && *output_ciphertext_modulus
                        == expected_bootstrapping_key_params.ciphertext_modulus
                    && *message_modulus == *expected_message_modulus
                    && *carry_modulus == *expected_carry_modulus
            }
            (
                SeededShortint128BootstrappingKey::MultiBit { bsk, .. },
                NoiseSquashingKeyConformanceParams::MultiBit {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                    message_modulus: expected_message_modulus,
                    carry_modulus: expected_carry_modulus,
                },
            ) => {
                bsk.is_conformant(expected_bootstrapping_key_params)
                    && *output_ciphertext_modulus
                        == expected_bootstrapping_key_params.ciphertext_modulus
                    && *message_modulus == *expected_message_modulus
                    && *carry_modulus == *expected_carry_modulus
            }
            _ => false,
        }
    }
}
