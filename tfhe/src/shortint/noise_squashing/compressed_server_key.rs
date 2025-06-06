use super::{NoiseSquashingKey, NoiseSquashingKeyConformanceParams, NoiseSquashingPrivateKey};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::lwe_bootstrap_key_conversion::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::algorithms::lwe_bootstrap_key_generation::par_allocate_and_generate_new_seeded_lwe_bootstrap_key;
use crate::core_crypto::commons::math::random::Seeder;
use crate::core_crypto::entities::{Fourier128LweBootstrapKeyOwned, SeededLweBootstrapKeyOwned};
use crate::shortint::backward_compatibility::noise_squashing::CompressedNoiseSquashingKeyVersions;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, CoreCiphertextModulus, MessageModulus};
use crate::shortint::server_key::{
    CompressedModulusSwitchNoiseReductionKey, ModulusSwitchNoiseReductionKeyConformanceParams,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedNoiseSquashingKeyVersions)]
pub struct CompressedNoiseSquashingKey {
    bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
    modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey<u64>>,
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

        assert_eq!(
            pbs_parameters.message_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .message_modulus,
            "Mismatched MessageModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            pbs_parameters.message_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .message_modulus
        );
        assert_eq!(
            pbs_parameters.carry_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .carry_modulus,
            "Mismatched CarryModulus between ClientKey {:?} and NoiseSquashingPrivateKey {:?}.",
            pbs_parameters.carry_modulus(),
            noise_squashing_private_key
                .noise_squashing_parameters()
                .carry_modulus
        );

        let noise_squashing_parameters = noise_squashing_private_key.noise_squashing_parameters();

        let (bootstrapping_key, modulus_switch_noise_reduction_key) =
            ShortintEngine::with_thread_local_mut(|engine| {
                let seeded_bsk = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &std_cks.lwe_secret_key,
                    noise_squashing_private_key.post_noise_squashing_secret_key(),
                    noise_squashing_parameters.decomp_base_log,
                    noise_squashing_parameters.decomp_level_count,
                    noise_squashing_parameters.glwe_noise_distribution,
                    noise_squashing_parameters.ciphertext_modulus,
                    &mut engine.seeder,
                );

                let modulus_switch_noise_reduction_key = noise_squashing_parameters
                    .modulus_switch_noise_reduction_params
                    .map(|p| {
                        let seed = engine.seeder.seed();
                        CompressedModulusSwitchNoiseReductionKey::new(
                            p,
                            &std_cks.lwe_secret_key,
                            engine,
                            pbs_parameters.ciphertext_modulus(),
                            pbs_parameters.lwe_noise_distribution(),
                            seed.into(),
                        )
                    });

                (seeded_bsk, modulus_switch_noise_reduction_key)
            });

        CompressedNoiseSquashingKey {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            output_ciphertext_modulus: noise_squashing_parameters.ciphertext_modulus,
            message_modulus: noise_squashing_parameters.message_modulus,
            carry_modulus: noise_squashing_parameters.carry_modulus,
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

    pub fn decompress(&self) -> NoiseSquashingKey {
        let (bootstrapping_key, modulus_switch_noise_reduction_key) = {
            let std_bsk = self
                .bootstrapping_key
                .as_view()
                .par_decompress_into_lwe_bootstrap_key();

            let mut fbsk = Fourier128LweBootstrapKeyOwned::new(
                std_bsk.input_lwe_dimension(),
                std_bsk.glwe_size(),
                std_bsk.polynomial_size(),
                std_bsk.decomposition_base_log(),
                std_bsk.decomposition_level_count(),
            );

            par_convert_standard_lwe_bootstrap_key_to_fourier_128(&std_bsk, &mut fbsk);

            (
                fbsk,
                self.modulus_switch_noise_reduction_key
                    .as_ref()
                    .map(|key| key.decompress()),
            )
        };

        NoiseSquashingKey {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            output_ciphertext_modulus: self.output_ciphertext_modulus,
        }
    }

    pub fn bootstrapping_key(&self) -> &SeededLweBootstrapKeyOwned<u128> {
        &self.bootstrapping_key
    }

    pub fn modulus_switch_noise_reduction_key(
        &self,
    ) -> Option<&CompressedModulusSwitchNoiseReductionKey<u64>> {
        self.modulus_switch_noise_reduction_key.as_ref()
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

    pub fn from_raw_parts(
        bootstrapping_key: SeededLweBootstrapKeyOwned<u128>,
        modulus_switch_noise_reduction_key: Option<CompressedModulusSwitchNoiseReductionKey<u64>>,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        output_ciphertext_modulus: CoreCiphertextModulus<u128>,
    ) -> Self {
        Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        }
    }
}

impl ParameterSetConformant for CompressedNoiseSquashingKey {
    type ParameterSet = NoiseSquashingKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            bootstrapping_key,
            modulus_switch_noise_reduction_key,
            message_modulus,
            carry_modulus,
            output_ciphertext_modulus,
        } = self;

        let Self::ParameterSet {
            bootstrapping_key_params: expected_bootstrapping_key_params,
            modulus_switch_noise_reduction_params: expected_modulus_switch_noise_reduction_params,
            message_modulus: expected_message_modulus,
            carry_modulus: expected_carry_modulus,
        } = parameter_set;

        let modulus_switch_key_ok = match (
            modulus_switch_noise_reduction_key,
            expected_modulus_switch_noise_reduction_params,
        ) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(_), None) => false,
            (Some(key), Some(params)) => {
                let mod_switch_conformance_params =
                    ModulusSwitchNoiseReductionKeyConformanceParams {
                        modulus_switch_noise_reduction_params: *params,
                        lwe_dimension: bootstrapping_key.input_lwe_dimension(),
                    };

                key.is_conformant(&mod_switch_conformance_params)
            }
        };

        modulus_switch_key_ok
            && bootstrapping_key.is_conformant(expected_bootstrapping_key_params)
            && *output_ciphertext_modulus == expected_bootstrapping_key_params.ciphertext_modulus
            && *message_modulus == *expected_message_modulus
            && *carry_modulus == *expected_carry_modulus
    }
}
