use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweBskGroupingFactor, LweDimension, PolynomialSize, ThreadCount,
};
use crate::core_crypto::commons::traits::{CastInto, Container, UnsignedInteger};
use crate::core_crypto::entities::*;
use crate::shortint::atomic_pattern::compressed::CompressedAtomicPatternServerKey;
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::ciphertext::MaxDegree;
use crate::shortint::parameters::KeySwitch32PBSParameters;
use crate::shortint::server_key::{ShortintBootstrappingKey, ShortintCompressedBootstrappingKey};
use crate::shortint::{
    CiphertextModulus, ClientKey, CompressedServerKey, PBSParameters, ServerKey,
};

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        // Plaintext Max Value
        let max_degree = MaxDegree::from_msg_carry_modulus(
            cks.parameters().message_modulus(),
            cks.parameters().carry_modulus(),
        );

        self.new_server_key_with_max_degree(cks, max_degree)
    }

    pub(crate) fn get_thread_count_for_multi_bit_pbs(
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
            4 => ThreadCount(9),
            _ => {
                todo!(
                    "Currently shortint only supports grouping factor 2, 3 and 4 for multi bit PBS"
                )
            }
        }
    }

    pub(crate) fn new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> ServerKey {
        let ap_key = AtomicPatternServerKey::new(cks, self);

        // Pack the keys in the server key set:
        ServerKey {
            atomic_pattern: ap_key,
            message_modulus: cks.parameters().message_modulus(),
            carry_modulus: cks.parameters().carry_modulus(),
            max_degree,
            max_noise_level: cks.parameters().max_noise_level(),
            ciphertext_modulus: cks.parameters().ciphertext_modulus(),
        }
    }

    pub fn new_bootstrapping_key_ks32<
        InKeycont: Container<Element = u32> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: KeySwitch32PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> ShortintBootstrappingKey<u32> {
        let bsk = self.new_classic_bootstrapping_key(
            in_key,
            out_key,
            pbs_params.glwe_noise_distribution,
            pbs_params.pbs_base_log,
            pbs_params.pbs_level,
            pbs_params.ciphertext_modulus,
        );
        let modulus_switch_noise_reduction_key = pbs_params
            .modulus_switch_noise_reduction_params
            .to_modulus_switch_configuration(
                in_key,
                pbs_params.post_keyswitch_ciphertext_modulus,
                pbs_params.lwe_noise_distribution,
                self,
            );

        ShortintBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        }
    }

    pub fn new_bootstrapping_key<
        InKeycont: Container<Element = u64> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params_base: PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> ShortintBootstrappingKey<u64> {
        match pbs_params_base {
            PBSParameters::PBS(pbs_params) => {
                let bsk = self.new_classic_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.ciphertext_modulus,
                );

                let modulus_switch_noise_reduction_key = pbs_params
                    .modulus_switch_noise_reduction_params
                    .to_modulus_switch_configuration(
                        in_key,
                        pbs_params.ciphertext_modulus,
                        pbs_params.lwe_noise_distribution,
                        self,
                    );

                ShortintBootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                }
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

                let thread_count = Self::get_thread_count_for_multi_bit_pbs(
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
        InputScalar: UnsignedInteger + CastInto<u64>,
        InKeycont: Container<Element = InputScalar>,
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

    pub(crate) fn new_compressed_server_key(&mut self, cks: &ClientKey) -> CompressedServerKey {
        // Plaintext Max Value
        let max_value =
            cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree::new(max_value);
        self.new_compressed_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn new_compressed_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> CompressedServerKey {
        let compressed_ap_server_key = CompressedAtomicPatternServerKey::new(cks, self);

        let params = cks.parameters();
        let message_modulus = params.message_modulus();
        let carry_modulus = params.carry_modulus();
        let max_noise_level = params.max_noise_level();

        // Pack the keys in the server key set:
        CompressedServerKey {
            compressed_ap_server_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        }
    }

    pub fn new_compressed_bootstrapping_key_ks32<
        InKeycont: Container<Element = u32> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params: KeySwitch32PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> ShortintCompressedBootstrappingKey<u32> {
        let bsk = self.new_compressed_classic_bootstrapping_key(
            in_key,
            out_key,
            pbs_params.glwe_noise_distribution,
            pbs_params.pbs_base_log,
            pbs_params.pbs_level,
            pbs_params.ciphertext_modulus,
        );
        let modulus_switch_noise_reduction_key = pbs_params
            .modulus_switch_noise_reduction_params
            .to_compressed_modulus_switch_configuration(
                in_key,
                pbs_params.post_keyswitch_ciphertext_modulus,
                pbs_params.lwe_noise_distribution,
                self,
            );

        ShortintCompressedBootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        }
    }

    pub fn new_compressed_bootstrapping_key<
        InKeycont: Container<Element = u64> + Sync,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        pbs_params_base: PBSParameters,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
    ) -> ShortintCompressedBootstrappingKey<u64> {
        match pbs_params_base {
            crate::shortint::PBSParameters::PBS(pbs_params) => {
                let bootstrapping_key = self.new_compressed_classic_bootstrapping_key(
                    in_key,
                    out_key,
                    pbs_params.glwe_noise_distribution,
                    pbs_params.pbs_base_log,
                    pbs_params.pbs_level,
                    pbs_params.ciphertext_modulus,
                );

                let modulus_switch_noise_reduction_key = pbs_params
                    .modulus_switch_noise_reduction_params
                    .to_compressed_modulus_switch_configuration(
                        in_key,
                        pbs_params.ciphertext_modulus,
                        pbs_params.lwe_noise_distribution,
                        self,
                    );

                ShortintCompressedBootstrappingKey::Classic {
                    bsk: bootstrapping_key,
                    modulus_switch_noise_reduction_key,
                }
            }
            crate::shortint::PBSParameters::MultiBitPBS(pbs_params) => {
                let bootstrapping_key =
                    if cfg!(feature = "__wasm_api") && !cfg!(feature = "parallel-wasm-api") {
                        // WASM and no parallelism -> sequential generation
                        allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                            in_key,
                            out_key,
                            pbs_params.pbs_base_log,
                            pbs_params.pbs_level,
                            pbs_params.glwe_noise_distribution,
                            pbs_params.grouping_factor,
                            pbs_params.ciphertext_modulus,
                            &mut self.seeder,
                        )
                    } else {
                        par_allocate_and_generate_new_seeded_lwe_multi_bit_bootstrap_key(
                            in_key,
                            out_key,
                            pbs_params.pbs_base_log,
                            pbs_params.pbs_level,
                            pbs_params.glwe_noise_distribution,
                            pbs_params.grouping_factor,
                            pbs_params.ciphertext_modulus,
                            &mut self.seeder,
                        )
                    };

                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bootstrapping_key,
                    deterministic_execution: pbs_params.deterministic_execution,
                }
            }
        }
    }

    pub fn new_compressed_classic_bootstrapping_key<
        InputScalar: UnsignedInteger + CastInto<u64>,
        InKeycont: Container<Element = InputScalar>,
        OutKeyCont: Container<Element = u64> + Sync,
    >(
        &mut self,
        in_key: &LweSecretKey<InKeycont>,
        out_key: &GlweSecretKey<OutKeyCont>,
        glwe_noise_distribution: DynamicDistribution<u64>,
        pbs_base_log: DecompositionBaseLog,
        pbs_level: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus,
    ) -> SeededLweBootstrapKeyOwned<u64> {
        if cfg!(feature = "__wasm_api") && !cfg!(feature = "parallel-wasm-api") {
            // WASM and no parallelism -> sequential generation
            allocate_and_generate_new_seeded_lwe_bootstrap_key(
                in_key,
                out_key,
                pbs_base_log,
                pbs_level,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut self.seeder,
            )
        } else {
            par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
                in_key,
                out_key,
                pbs_base_log,
                pbs_level,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut self.seeder,
            )
        }
    }
}
