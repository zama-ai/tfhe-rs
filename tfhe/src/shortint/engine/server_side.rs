use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweBskGroupingFactor,
    LweDimension, PolynomialSize, ThreadCount,
};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::shortint::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::parameters::{MessageModulus, ShortintKeySwitchingParameters};
use crate::shortint::server_key::add::unchecked_add_assign;
use crate::shortint::server_key::{
    BivariateLookupTableOwned, LookupTableOwned, MaxDegree, ShortintBootstrappingKey,
    ShortintCompressedBootstrappingKey,
};
use crate::shortint::{Ciphertext, ClientKey, CompressedServerKey, PBSOrder, ServerKey};

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree(max_value);
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
        let max = MaxDegree(max_value);
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

    pub(crate) fn keyswitch_programmable_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (mut ciphertext_buffers, buffers) = self.get_buffers(server_key);

        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ct.ct,
            &mut ciphertext_buffers.buffer_lwe_after_ks,
        );

        match &server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(fourier_bsk) => {
                let fft = Fft::new(fourier_bsk.polynomial_size());
                let fft = fft.as_view();
                buffers.resize(
                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                        fourier_bsk.glwe_size(),
                        fourier_bsk.polynomial_size(),
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                let stack = buffers.stack();

                // Compute a bootstrap
                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    &ciphertext_buffers.buffer_lwe_after_ks,
                    &mut ct.ct,
                    &acc.acc,
                    fourier_bsk,
                    fft,
                    stack,
                );
            }
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                thread_count,
                deterministic_execution,
            } => {
                if *deterministic_execution {
                    multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        &mut ct.ct,
                        &acc.acc,
                        fourier_bsk,
                        *thread_count,
                    );
                } else {
                    multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        &mut ct.ct,
                        &acc.acc,
                        fourier_bsk,
                        *thread_count,
                    );
                }
            }
        };

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }

    pub(crate) fn unchecked_apply_lookup_table_bivariate(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_apply_lookup_table_bivariate_assign(server_key, &mut ct_res, ct_right, acc);
        ct_res
    }

    pub(crate) fn unchecked_apply_lookup_table_bivariate_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        let modulus = (ct_right.degree.0 + 1) as u64;
        assert!(modulus <= acc.ct_right_modulus.0 as u64);

        // Message 1 is shifted
        server_key.unchecked_scalar_mul_assign(ct_left, acc.ct_right_modulus.0 as u8);

        unchecked_add_assign(ct_left, ct_right);

        // Compute the PBS
        self.apply_lookup_table_assign(server_key, ct_left, &acc.acc);
    }

    pub(crate) fn unchecked_evaluate_bivariate_function<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_evaluate_bivariate_function_assign(server_key, &mut ct_res, ct_right, f);
        ct_res
    }

    pub(crate) fn unchecked_evaluate_bivariate_function_assign<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the lookup _table for the function
        let factor = MessageModulus(ct_right.degree.0 + 1);
        let lookup_table = server_key.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(
            server_key,
            ct_left,
            ct_right,
            &lookup_table,
        );
    }

    pub(crate) fn smart_evaluate_bivariate_function<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        if server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // We don't have enough space in carries, so clear them
            self.message_extract_assign(server_key, ct_left);
            self.message_extract_assign(server_key, ct_right);
        }
        server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        let factor = MessageModulus(ct_right.degree.0 + 1);

        // Generate the lookup table for the function
        let lookup_table = server_key.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate(server_key, ct_left, ct_right, &lookup_table)
    }

    pub(crate) fn smart_evaluate_bivariate_function_assign<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        if server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // We don't have enough space in carries, so clear them
            self.message_extract_assign(server_key, ct_left);
            self.message_extract_assign(server_key, ct_right);
        }
        server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        let factor = MessageModulus(ct_right.degree.0 + 1);

        // Generate the lookup table for the function
        let lookup_table = server_key.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(
            server_key,
            ct_left,
            ct_right,
            &lookup_table,
        );
    }

    pub(crate) fn smart_apply_lookup_table_bivariate(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        if server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(server_key, ct_left);
            self.message_extract_assign(server_key, ct_right);
        }

        server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate(server_key, ct_left, ct_right, acc)
    }

    pub(crate) fn smart_apply_lookup_table_bivariate_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        if server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(server_key, ct_left);
            self.message_extract_assign(server_key, ct_right);
        }

        server_key
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate_assign(server_key, ct_left, ct_right, acc);
    }

    pub(crate) fn programmable_bootstrap_keyswitch_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        let (mut ciphertext_buffers, buffers) = self.get_buffers(server_key);

        match &server_key.bootstrapping_key {
            ShortintBootstrappingKey::Classic(fourier_bsk) => {
                let fft = Fft::new(fourier_bsk.polynomial_size());
                let fft = fft.as_view();
                buffers.resize(
                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                        fourier_bsk.glwe_size(),
                        fourier_bsk.polynomial_size(),
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );
                let stack = buffers.stack();

                // Compute a bootstrap
                programmable_bootstrap_lwe_ciphertext_mem_optimized(
                    &ct.ct,
                    &mut ciphertext_buffers.buffer_lwe_after_pbs,
                    &acc.acc,
                    fourier_bsk,
                    fft,
                    stack,
                );
            }
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                thread_count,
                deterministic_execution,
            } => {
                if *deterministic_execution {
                    multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        &acc.acc,
                        fourier_bsk,
                        *thread_count,
                    );
                } else {
                    multi_bit_programmable_bootstrap_lwe_ciphertext(
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        &acc.acc,
                        fourier_bsk,
                        *thread_count,
                    );
                }
            }
        };

        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext_buffers.buffer_lwe_after_pbs,
            &mut ct.ct,
        );

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }

    pub(crate) fn apply_lookup_table_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                // This updates the ciphertext degree
                self.keyswitch_programmable_bootstrap_assign(server_key, ct, acc);
            }
            PBSOrder::BootstrapKeyswitch => {
                // This updates the ciphertext degree
                self.programmable_bootstrap_keyswitch_assign(server_key, ct, acc);
            }
        };
    }

    pub(crate) fn apply_lookup_table(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        acc: &LookupTableOwned,
    ) -> Ciphertext {
        let mut ct_res = ct.clone();

        self.apply_lookup_table_assign(server_key, &mut ct_res, acc);

        ct_res
    }

    pub(crate) fn carry_extract_assign(&mut self, server_key: &ServerKey, ct: &mut Ciphertext) {
        let modulus = ct.message_modulus.0 as u64;

        let lookup_table = server_key.generate_lookup_table(|x| x / modulus);

        self.apply_lookup_table_assign(server_key, ct, &lookup_table);
    }

    pub(crate) fn carry_extract(&mut self, server_key: &ServerKey, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.carry_extract_assign(server_key, &mut result);
        result
    }

    pub(crate) fn message_extract_assign(&mut self, server_key: &ServerKey, ct: &mut Ciphertext) {
        let acc = server_key.generate_msg_lookup_table(|x| x, ct.message_modulus);

        self.apply_lookup_table_assign(server_key, ct, &acc);
    }

    pub(crate) fn message_extract(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> Ciphertext {
        let mut result = ct.clone();
        self.message_extract_assign(server_key, &mut result);
        result
    }

    // Impossible to call the assign function in this case
    pub(crate) fn create_trivial(
        &mut self,
        server_key: &ServerKey,
        value: u64,
        ciphertext_modulus: CiphertextModulus<u64>,
    ) -> Ciphertext {
        let lwe_size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .bootstrapping_key
                .output_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            lwe_size,
            encoded,
            ciphertext_modulus,
        );

        let degree = Degree(modular_value);

        Ciphertext::new(
            ct,
            degree,
            NoiseLevel::ZERO,
            server_key.message_modulus,
            server_key.carry_modulus,
            server_key.pbs_order,
        )
    }

    pub(crate) fn create_trivial_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        value: u64,
    ) {
        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        trivially_encrypt_lwe_ciphertext(&mut ct.ct, encoded);

        ct.degree = Degree(modular_value);
        ct.set_noise_level(NoiseLevel::ZERO);
    }
}
