use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweDimension, PolynomialSize, ThreadCount,
};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::shortint::ciphertext::{MaxDegree, MaxNoiseLevel};
use crate::shortint::parameters::ShortintKeySwitchingParameters;
use crate::shortint::server_key::{ShortintBootstrappingKey, ShortintCompressedBootstrappingKey};
use crate::shortint::{ClientKey, CompressedServerKey, ServerKey};

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree::new(max_value);
        self.new_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn get_thread_count_for_multi_bit_pbs(
        &self,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
    ) -> ThreadCount {
        // TODO
        // Will be used later when we dynamically compute thread counts, put them in the public
        // signature of the function for now
        let _ = (
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );

        // For now optimal threads for m6i.metal across 1_1, 2_2, 3_3 and 4_4 params
        match grouping_factor.0 {
            2 => ThreadCount(5),
            3 => ThreadCount(7),
            _ => {
                todo!("Currently shortint only supports grouping factor 2 and 3 for multi bit PBS")
            }
        }
    }

    pub(crate) fn new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> ServerKey {
        let params = &cks.parameters;
        let pbs_params_base = params.pbs_parameters().unwrap();
        let bootstrapping_key_base = match pbs_params_base {
            crate::shortint::PBSParameters::PBS(pbs_params) => {
                let bootstrap_key: LweBootstrapKeyOwned<u64> =
                    par_allocate_and_generate_new_lwe_bootstrap_key(
                        &cks.small_lwe_secret_key,
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_modular_std_dev,
                        pbs_params.ciphertext_modulus,
                        &mut self.encryption_generator,
                    );

                // Creation of the bootstrapping key in the Fourier domain
                let mut fourier_bsk = FourierLweBootstrapKey::new(
                    bootstrap_key.input_lwe_dimension(),
                    bootstrap_key.glwe_size(),
                    bootstrap_key.polynomial_size(),
                    bootstrap_key.decomposition_base_log(),
                    bootstrap_key.decomposition_level_count(),
                );

                // Conversion to fourier domain
                par_convert_standard_lwe_bootstrap_key_to_fourier(&bootstrap_key, &mut fourier_bsk);

                ShortintBootstrappingKey::Classic(fourier_bsk)
            }
            crate::shortint::PBSParameters::MultiBitPBS(pbs_params) => {
                let bootstrap_key: LweMultiBitBootstrapKeyOwned<u64> =
                    par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
                        &cks.small_lwe_secret_key,
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.grouping_factor,
                        pbs_params.glwe_modular_std_dev,
                        pbs_params.ciphertext_modulus,
                        &mut self.encryption_generator,
                    );

                // Creation of the bootstrapping key in the Fourier domain
                let mut fourier_bsk = FourierLweMultiBitBootstrapKey::new(
                    bootstrap_key.input_lwe_dimension(),
                    bootstrap_key.glwe_size(),
                    bootstrap_key.polynomial_size(),
                    bootstrap_key.decomposition_base_log(),
                    bootstrap_key.decomposition_level_count(),
                    bootstrap_key.grouping_factor(),
                );

                // Conversion to fourier domain
                par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(
                    &bootstrap_key,
                    &mut fourier_bsk,
                );

                let thread_count = self.get_thread_count_for_multi_bit_pbs(
                    pbs_params.lwe_dimension,
                    pbs_params.glwe_dimension,
                    pbs_params.polynomial_size,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.grouping_factor,
                );
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution: pbs_params.deterministic_execution,
                }
            }
        };

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.large_lwe_secret_key,
            &cks.small_lwe_secret_key,
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            cks.parameters.lwe_modular_std_dev(),
            cks.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(
            cks.parameters.message_modulus(),
            cks.parameters.carry_modulus(),
        );

        // Pack the keys in the server key set:
        ServerKey {
            key_switching_key,
            bootstrapping_key: bootstrapping_key_base,
            message_modulus: cks.parameters.message_modulus(),
            carry_modulus: cks.parameters.carry_modulus(),
            max_degree,
            max_noise_level,
            ciphertext_modulus: cks.parameters.ciphertext_modulus(),
            pbs_order: cks.parameters.encryption_key_choice().into(),
        }
    }

    pub(crate) fn new_key_switching_key(
        &mut self,
        cks1: &ClientKey,
        cks2: &ClientKey,
        params: ShortintKeySwitchingParameters,
    ) -> LweKeyswitchKeyOwned<u64> {
        // Creation of the key switching key
        allocate_and_generate_new_lwe_keyswitch_key(
            &cks1.large_lwe_secret_key,
            &cks2.large_lwe_secret_key,
            params.ks_base_log,
            params.ks_level,
            cks2.parameters.lwe_modular_std_dev(),
            cks2.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        )
    }

    pub(crate) fn new_compressed_server_key(&mut self, cks: &ClientKey) -> CompressedServerKey {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree::new(max_value);
        self.new_compressed_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn new_compressed_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> CompressedServerKey {
        let bootstrapping_key = match cks.parameters.pbs_parameters().unwrap() {
            crate::shortint::PBSParameters::PBS(pbs_params) => {
                #[cfg(not(feature = "__wasm_api"))]
                let bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &cks.small_lwe_secret_key,
                    &cks.glwe_secret_key,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.glwe_modular_std_dev,
                    pbs_params.ciphertext_modulus,
                    &mut self.seeder,
                );

                #[cfg(feature = "__wasm_api")]
                let bootstrapping_key = allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &cks.small_lwe_secret_key,
                    &cks.glwe_secret_key,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.glwe_modular_std_dev,
                    pbs_params.ciphertext_modulus,
                    &mut self.seeder,
                );

                ShortintCompressedBootstrappingKey::Classic(bootstrapping_key)
            }
            crate::shortint::PBSParameters::MultiBitPBS(pbs_params) => {
                #[cfg(not(feature = "__wasm_api"))]
                let bootstrapping_key =
                    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                        &cks.small_lwe_secret_key,
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_modular_std_dev,
                        pbs_params.grouping_factor,
                        pbs_params.ciphertext_modulus,
                        &mut self.seeder,
                    );

                #[cfg(feature = "__wasm_api")]
                let bootstrapping_key =
                    allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                        &cks.small_lwe_secret_key,
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_modular_std_dev,
                        pbs_params.grouping_factor,
                        pbs_params.ciphertext_modulus,
                        &mut self.seeder,
                    );

                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bootstrapping_key,
                    deterministic_execution: pbs_params.deterministic_execution,
                }
            }
        };

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &cks.large_lwe_secret_key,
            &cks.small_lwe_secret_key,
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            cks.parameters.lwe_modular_std_dev(),
            cks.parameters.ciphertext_modulus(),
            &mut self.seeder,
        );

        // Pack the keys in the server key set:
        CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus: cks.parameters.message_modulus(),
            carry_modulus: cks.parameters.carry_modulus(),
            max_degree,
            ciphertext_modulus: cks.parameters.ciphertext_modulus(),
            pbs_order: cks.parameters.encryption_key_choice().into(),
        }
    }
}
