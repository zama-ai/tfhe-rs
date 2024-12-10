use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweBskGroupingFactor, LweDimension, PolynomialSize, ThreadCount,
};
use crate::core_crypto::commons::traits::Container;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::shortint::parameters::{EncryptionKeyChoice, ShortintKeySwitchingParameters};
use crate::shortint::server_key::{ShortintBootstrappingKey, ShortintCompressedBootstrappingKey};
use crate::shortint::{
    CiphertextModulus, ClientKey, CompressedServerKey, PBSParameters, ServerKey,
};

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        // Plaintext Max Value
        let max_degree = MaxDegree::from_msg_carry_modulus(
            cks.parameters.message_modulus(),
            cks.parameters.carry_modulus(),
        );

        self.new_server_key_with_max_degree(cks, max_degree)
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

        let in_key = &cks.small_lwe_secret_key();

        let out_key = &cks.glwe_secret_key;

        let bootstrapping_key_base = self.new_bootstrapping_key(pbs_params_base, in_key, out_key);

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.large_lwe_secret_key(),
            &cks.small_lwe_secret_key(),
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            cks.parameters.lwe_noise_distribution(),
            cks.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        );

        // Pack the keys in the server key set:
        ServerKey {
            key_switching_key,
            bootstrapping_key: bootstrapping_key_base,
            message_modulus: cks.parameters.message_modulus(),
            carry_modulus: cks.parameters.carry_modulus(),
            max_degree,
            max_noise_level: cks.parameters.max_noise_level(),
            ciphertext_modulus: cks.parameters.ciphertext_modulus(),
            pbs_order: cks.parameters.encryption_key_choice().into(),
        }
    }

    pub fn new_bootstrapping_key<
        InKeycont: Container<Element = u64>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params_base: PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> ShortintBootstrappingKey {
        match pbs_params_base {
            PBSParameters::PBS(pbs_params) => {
                ShortintBootstrappingKey::Classic(self.new_classic_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.ciphertext_modulus,
                ))
            }
            PBSParameters::MultiBitPBS(pbs_params) => {
                let fourier_bsk = self.new_multibit_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.grouping_factor,
                    pbs_params.ciphertext_modulus,
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
        }
    }

    pub fn new_classic_bootstrapping_key<
        InKeycont: Container<Element = u64>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
        glwe_noise_distribution: DynamicDistribution<u64>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus,
    ) -> FourierLweBootstrapKeyOwned {
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                in_key,
                out_key,
                pbs_base_log,
                pbs_level,
                glwe_noise_distribution,
                ciphertext_modulus,
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

        fourier_bsk
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_multibit_bootstrapping_key<
        InKeycont: Container<Element = u64>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
        glwe_noise_distribution: DynamicDistribution<u64>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        ciphertext_modulus: CiphertextModulus,
    ) -> FourierLweMultiBitBootstrapKeyOwned {
        let bootstrap_key: LweMultiBitBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_multi_bit_bootstrap_key(
                in_key,
                out_key,
                pbs_base_log,
                pbs_level,
                grouping_factor,
                glwe_noise_distribution,
                ciphertext_modulus,
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
        fourier_bsk
    }

    pub(crate) fn new_key_switching_key(
        &mut self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        output_client_key: &ClientKey,
        params: ShortintKeySwitchingParameters,
    ) -> LweKeyswitchKeyOwned<u64> {
        let (output_secret_key, encryption_noise) = match params.destination_key {
            EncryptionKeyChoice::Big => (
                output_client_key.large_lwe_secret_key(),
                output_client_key.parameters.glwe_noise_distribution(),
            ),
            EncryptionKeyChoice::Small => (
                output_client_key.small_lwe_secret_key(),
                output_client_key.parameters.lwe_noise_distribution(),
            ),
        };

        // Creation of the key switching key
        allocate_and_generate_new_lwe_keyswitch_key(
            &input_secret_key.lwe_secret_key,
            &output_secret_key,
            params.ks_base_log,
            params.ks_level,
            encryption_noise,
            output_client_key.parameters.ciphertext_modulus(),
            &mut self.encryption_generator,
        )
    }

    pub(crate) fn new_seeded_key_switching_key(
        &mut self,
        input_secret_key: &SecretEncryptionKeyView<'_>,
        output_client_key: &ClientKey,
        params: ShortintKeySwitchingParameters,
    ) -> SeededLweKeyswitchKeyOwned<u64> {
        let (output_secret_key, encryption_noise) = match params.destination_key {
            EncryptionKeyChoice::Big => (
                output_client_key.large_lwe_secret_key(),
                output_client_key.parameters.glwe_noise_distribution(),
            ),
            EncryptionKeyChoice::Small => (
                output_client_key.small_lwe_secret_key(),
                output_client_key.parameters.lwe_noise_distribution(),
            ),
        };

        // Creation of the key switching key
        allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &input_secret_key.lwe_secret_key,
            &output_secret_key,
            params.ks_base_log,
            params.ks_level,
            encryption_noise,
            output_client_key.parameters.ciphertext_modulus(),
            &mut self.seeder,
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
                #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
                let bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &cks.small_lwe_secret_key(),
                    &cks.glwe_secret_key,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.ciphertext_modulus,
                    &mut self.seeder,
                );

                #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
                let bootstrapping_key = allocate_and_generate_new_seeded_lwe_bootstrap_key(
                    &cks.small_lwe_secret_key(),
                    &cks.glwe_secret_key,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.ciphertext_modulus,
                    &mut self.seeder,
                );

                ShortintCompressedBootstrappingKey::Classic(bootstrapping_key)
            }
            crate::shortint::PBSParameters::MultiBitPBS(pbs_params) => {
                #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
                let bootstrapping_key =
                    par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                        &cks.small_lwe_secret_key(),
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_noise_distribution,
                        pbs_params.grouping_factor,
                        pbs_params.ciphertext_modulus,
                        &mut self.seeder,
                    );

                #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
                let bootstrapping_key =
                    allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                        &cks.small_lwe_secret_key(),
                        &cks.glwe_secret_key,
                        pbs_params.pbs_base_log,
                        pbs_params.pbs_level,
                        pbs_params.glwe_noise_distribution,
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
            &cks.large_lwe_secret_key(),
            &cks.small_lwe_secret_key(),
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            cks.parameters.lwe_noise_distribution(),
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
            max_noise_level: cks.parameters.max_noise_level(),
            ciphertext_modulus: cks.parameters.ciphertext_modulus(),
            pbs_order: cks.parameters.encryption_key_choice().into(),
        }
    }
}
