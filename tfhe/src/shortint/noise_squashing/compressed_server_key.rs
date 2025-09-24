use super::atomic_pattern::compressed::CompressedAtomicPatternNoiseSquashingKey;
use super::server_key::Shortint128BootstrappingKeyConformanceParams;
use super::{NoiseSquashingKey, NoiseSquashingKeyConformanceParams, NoiseSquashingPrivateKey};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_seeded_lwe_bootstrap_key;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, SeededLweBootstrapKeyOwned};
use crate::core_crypto::prelude::{
    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key,
    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier_128, CastFrom, Container,
    DynamicDistribution, Encryptable, Fourier128LweMultiBitBootstrapKey, LweSecretKey,
    SeededLweMultiBitBootstrapKeyOwned, ThreadCount, UnsignedInteger, UnsignedTorus,
};
use crate::shortint::backward_compatibility::noise_squashing::{
    CompressedNoiseSquashingKeyVersions, CompressedShortint128BootstrappingKeyVersions,
};

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
use crate::shortint::AtomicPatternKind;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedShortint128BootstrappingKeyVersions)]
pub enum CompressedShortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    Classic {
        bsk: SeededLweBootstrapKeyOwned<u128>,
        modulus_switch_noise_reduction_key: CompressedModulusSwitchConfiguration<Scalar>,
    },
    MultiBit {
        bsk: SeededLweMultiBitBootstrapKeyOwned<u128>,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

impl<Scalar> CompressedShortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedTorus,
{
    pub(crate) fn new<InputKeyCont>(
        input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
        ciphertext_modulus: CoreCiphertextModulus<Scalar>,
        lwe_noise_distribution: DynamicDistribution<Scalar>,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> Self
    where
        InputKeyCont: Container<Element = Scalar> + Sync,
        Scalar: Encryptable<Uniform, DynamicDistribution<Scalar>> + CastFrom<usize>,
    {
        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        match noise_squashing_parameters {
            NoiseSquashingParameters::Classic(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let seeded_bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                        input_lwe_secret_key,
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
                            input_lwe_secret_key,
                            ciphertext_modulus,
                            lwe_noise_distribution,
                            engine,
                        );

                    Self::Classic {
                        bsk: seeded_bsk,
                        modulus_switch_noise_reduction_key,
                    }
                })
            }
            NoiseSquashingParameters::MultiBit(params) => {
                ShortintEngine::with_thread_local_mut(|engine| {
                    let seeded_bsk =
                        par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                            input_lwe_secret_key,
                            noise_squashing_private_key.post_noise_squashing_secret_key(),
                            params.decomp_base_log,
                            params.decomp_level_count,
                            params.glwe_noise_distribution,
                            params.grouping_factor,
                            params.ciphertext_modulus,
                            &mut engine.seeder,
                        );

                    let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                        input_lwe_secret_key.lwe_dimension(),
                        params.glwe_dimension,
                        params.polynomial_size,
                        params.decomp_base_log,
                        params.decomp_level_count,
                        params.grouping_factor,
                    );

                    Self::MultiBit {
                        bsk: seeded_bsk,
                        thread_count,
                        deterministic_execution: params.deterministic_execution,
                    }
                })
            }
        }
    }

    pub(super) fn decompress(&self) -> Shortint128BootstrappingKey<Scalar> {
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

impl<Scalar> ParameterSetConformant for CompressedShortint128BootstrappingKey<Scalar>
where
    Scalar: UnsignedInteger,
{
    type ParameterSet = Shortint128BootstrappingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                Shortint128BootstrappingKeyConformanceParams::Classic {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                    modulus_switch_noise_reduction_params:
                        expected_modulus_switch_noise_reduction_params,
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

                modulus_switch_key_ok && bsk.is_conformant(expected_bootstrapping_key_params)
            }
            (
                Self::MultiBit { bsk, .. },
                Shortint128BootstrappingKeyConformanceParams::MultiBit {
                    bootstrapping_key_params: expected_bootstrapping_key_params,
                },
            ) => bsk.is_conformant(expected_bootstrapping_key_params),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingKeyVersions)]
pub struct CompressedNoiseSquashingKey {
    atomic_pattern: CompressedAtomicPatternNoiseSquashingKey,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    output_ciphertext_modulus: CoreCiphertextModulus<u128>,
}

impl ClientKey {
    pub fn new_compressed_noise_squashing_key(
        &self,
        noise_squashing_private_key: &NoiseSquashingPrivateKey,
    ) -> CompressedNoiseSquashingKey {
        let compute_parameters = self.parameters();

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        assert_eq!(
            compute_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus(),
            "Mismatched MessageModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            compute_parameters.message_modulus(),
            noise_squashing_parameters.message_modulus()
        );
        assert_eq!(
            compute_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus(),
            "Mismatched CarryModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            compute_parameters.carry_modulus(),
            noise_squashing_parameters.carry_modulus()
        );

        let atomic_pattern = CompressedAtomicPatternNoiseSquashingKey::new(
            &self.atomic_pattern,
            noise_squashing_private_key,
        );

        CompressedNoiseSquashingKey {
            atomic_pattern,
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
        atomic_pattern: CompressedAtomicPatternNoiseSquashingKey,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> Self {
        Self {
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        }
    }

    pub fn atomic_pattern(&self) -> &CompressedAtomicPatternNoiseSquashingKey {
        &self.atomic_pattern
    }

    pub fn decompress(&self) -> NoiseSquashingKey {
        NoiseSquashingKey::from_raw_parts(
            self.atomic_pattern.decompress(),
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
            atomic_pattern,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let bsk_conformant = match (atomic_pattern, parameter_set.atomic_pattern) {
            (
                CompressedAtomicPatternNoiseSquashingKey::Standard(compressed_std),
                AtomicPatternKind::Standard(_),
            ) => compressed_std
                .bootstrapping_key()
                .is_conformant(&parameter_set.pbs_params),
            (
                CompressedAtomicPatternNoiseSquashingKey::KeySwitch32(compressed_ks32),
                AtomicPatternKind::KeySwitch32,
            ) => compressed_ks32
                .bootstrapping_key()
                .is_conformant(&parameter_set.pbs_params),
            _ => false,
        };

        bsk_conformant
            && *output_ciphertext_modulus == parameter_set.output_ciphertext_modulus
            && *message_modulus == parameter_set.message_modulus
            && *carry_modulus == parameter_set.carry_modulus
    }
}
