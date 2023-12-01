//! # WARNING: this module is experimental.
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::shortint::ciphertext::{MaxDegree, MaxNoiseLevel};
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::server_key::ShortintBootstrappingKey;
use crate::shortint::wopbs::{WopbsKey, WopbsKeyCreationError};
use crate::shortint::{ClientKey, ServerKey, WopbsParameters};

impl ShortintEngine {
    // Creates a key when ONLY a wopbs is used.
    pub(crate) fn new_wopbs_key_only_for_wopbs(
        &mut self,
        cks: &ClientKey,
        sks: &ServerKey,
    ) -> EngineResult<WopbsKey> {
        if matches!(
            sks.bootstrapping_key,
            ShortintBootstrappingKey::MultiBit { .. }
        ) {
            return Err(WopbsKeyCreationError::UnsupportedMultiBit.into());
        }

        let wop_params = cks.parameters.wopbs_parameters().unwrap();

        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &cks.large_lwe_secret_key,
            &cks.glwe_secret_key,
            wop_params.pfks_base_log,
            wop_params.pfks_level,
            wop_params.pfks_modular_std_dev,
            wop_params.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        let sks_cpy = sks.clone();

        let wopbs_key = WopbsKey {
            wopbs_server_key: sks_cpy.clone(),
            cbs_pfpksk,
            ksk_pbs_to_wopbs: sks.key_switching_key.clone(),
            param: wop_params,
            pbs_server_key: sks_cpy,
        };
        Ok(wopbs_key)
    }

    //Creates a new WoPBS key.
    pub(crate) fn new_wopbs_key(
        &mut self,
        cks: &ClientKey,
        sks: &ServerKey,
        parameters: &WopbsParameters,
    ) -> WopbsKey {
        //Independent client key generation dedicated to the WoPBS
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

        //BSK dedicated to the WoPBS
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &small_lwe_secret_key,
                &glwe_secret_key,
                parameters.pbs_base_log,
                parameters.pbs_level,
                parameters.glwe_modular_std_dev,
                parameters.ciphertext_modulus,
                &mut self.encryption_generator,
            );

        // Creation of the bootstrapping key in the Fourier domain
        let mut small_bsk = FourierLweBootstrapKey::new(
            bootstrap_key.input_lwe_dimension(),
            bootstrap_key.glwe_size(),
            bootstrap_key.polynomial_size(),
            bootstrap_key.decomposition_base_log(),
            bootstrap_key.decomposition_level_count(),
        );

        // Conversion to fourier domain
        par_convert_standard_lwe_bootstrap_key_to_fourier(&bootstrap_key, &mut small_bsk);

        //KSK encryption_key -> small WoPBS key (used in the 1st KS in the extract bit)
        let ksk_wopbs_large_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_secret_key,
            &small_lwe_secret_key,
            parameters.ks_base_log,
            parameters.ks_level,
            parameters.lwe_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        // KSK to convert from input ciphertext key to the wopbs input one
        let ksk_pbs_large_to_wopbs_large = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.large_lwe_secret_key,
            &large_lwe_secret_key,
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            parameters.lwe_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        // KSK large_wopbs_key -> small PBS key (used after the WoPBS computation to compute a
        // classical PBS. This allows compatibility between PBS and WoPBS
        let ksk_wopbs_large_to_pbs_small = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_secret_key,
            &cks.small_lwe_secret_key,
            cks.parameters.ks_base_log(),
            cks.parameters.ks_level(),
            cks.parameters.lwe_modular_std_dev(),
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &large_lwe_secret_key,
            &glwe_secret_key,
            parameters.pfks_base_log,
            parameters.pfks_level,
            parameters.pfks_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        let max_noise_level_wopbs = MaxNoiseLevel::from_msg_carry_modulus(
            parameters.message_modulus,
            parameters.carry_modulus,
        );

        let wopbs_server_key = ServerKey {
            key_switching_key: ksk_wopbs_large_to_wopbs_small,
            bootstrapping_key: ShortintBootstrappingKey::Classic(small_bsk),
            message_modulus: parameters.message_modulus,
            carry_modulus: parameters.carry_modulus,
            max_degree: MaxDegree::from_msg_carry_modulus(
                parameters.message_modulus,
                parameters.carry_modulus,
            ),
            max_noise_level: max_noise_level_wopbs,
            ciphertext_modulus: parameters.ciphertext_modulus,
            pbs_order: cks.parameters.encryption_key_choice().into(),
        };

        let max_noise_level_pbs = MaxNoiseLevel::from_msg_carry_modulus(
            cks.parameters.message_modulus(),
            cks.parameters.carry_modulus(),
        );

        let pbs_server_key = ServerKey {
            key_switching_key: ksk_wopbs_large_to_pbs_small,
            bootstrapping_key: sks.bootstrapping_key.clone(),
            message_modulus: cks.parameters.message_modulus(),
            carry_modulus: cks.parameters.carry_modulus(),
            max_degree: MaxDegree::from_msg_carry_modulus(
                cks.parameters.message_modulus(),
                cks.parameters.carry_modulus(),
            ),
            max_noise_level: max_noise_level_pbs,
            ciphertext_modulus: cks.parameters.ciphertext_modulus(),
            pbs_order: cks.parameters.encryption_key_choice().into(),
        };

        WopbsKey {
            wopbs_server_key,
            pbs_server_key,
            cbs_pfpksk,
            ksk_pbs_to_wopbs: ksk_pbs_large_to_wopbs_large,
            param: *parameters,
        }
    }
}
