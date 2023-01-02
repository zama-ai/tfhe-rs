use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::math::fft::Fft;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::EngineResult;
use crate::shortint::server_key::MaxDegree;
use crate::shortint::{Ciphertext, ClientKey, ServerKey};
use std::cmp::min;

mod add;
mod bitwise_op;
mod comp_op;
mod div_mod;
mod mul;
mod neg;
mod scalar_add;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> EngineResult<ServerKey> {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree(max_value);
        self.new_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn bc_new_server_key(&mut self, cks: &ClientKey) -> EngineResult<ServerKey> {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree(max_value);
        self.bc_new_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn bc_new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> EngineResult<ServerKey> {
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
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

        let fft = Fft::new(bootstrap_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &bootstrap_key,
            &mut fourier_bsk,
            fft,
            stack,
        );

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.lwe_secret_key_after_ks,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        // Pack the keys in the server key set:
        Ok(ServerKey {
            key_switching_key,
            bootstrapping_key: fourier_bsk,
            message_modulus: cks.parameters.message_modulus,
            carry_modulus: cks.parameters.carry_modulus,
            max_degree,
        })
    }


    pub(crate) fn new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> EngineResult<ServerKey> {
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key_after_ks,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
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

        let fft = Fft::new(bootstrap_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &bootstrap_key,
            &mut fourier_bsk,
            fft,
            stack,
        );

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.lwe_secret_key,
            &cks.lwe_secret_key_after_ks,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        // Pack the keys in the server key set:
        Ok(ServerKey {
            key_switching_key,
            bootstrapping_key: fourier_bsk,
            message_modulus: cks.parameters.message_modulus,
            carry_modulus: cks.parameters.carry_modulus,
            max_degree,
        })
    }

    pub(crate) fn generate_accumulator<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertextOwned<u64>>
    where
        F: Fn(u64) -> u64,
    {
        Self::generate_accumulator_with_engine(server_key, f)
    }

    pub(crate) fn keyswitch_bootstrap(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut ct_in = ct.clone();
        self.keyswitch_bootstrap_assign(server_key, &mut ct_in)?;
        Ok(ct_in)
    }

    pub(crate) fn keyswitch_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (ciphertext_buffers, buffers) = self.buffers_for_key(server_key);

        // Compute a keyswitch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ct.ct,
            &mut ciphertext_buffers.buffer_lwe_after_ks,
        );

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_scratch::<u64>(
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
            &ciphertext_buffers.accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        Ok(())
    }

    pub(crate) fn keyswitch_programmable_bootstrap(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<Ciphertext> {
        let mut ct_res = ct.clone();
        self.keyswitch_programmable_bootstrap_assign(server_key, &mut ct_res, acc)?;
        Ok(ct_res)
    }

    pub(crate) fn keyswitch_programmable_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (ciphertext_buffers, buffers) = self.buffers_for_key(server_key);

        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ct.ct,
            &mut ciphertext_buffers.buffer_lwe_after_ks,
        );

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_scratch::<u64>(
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
            acc,
            fourier_bsk,
            fft,
            stack,
        );
        Ok(())
    }

    pub(crate) fn keyswitch_programmable_bootstrap_bivariate(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<Ciphertext> {
        let mut ct_res = ct_left.clone();
        self.keyswitch_programmable_bootstrap_bivariate_assign(
            server_key,
            &mut ct_res,
            ct_right,
            acc,
        )?;
        Ok(ct_res)
    }

    pub(crate) fn keyswitch_programmable_bootstrap_bivariate_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;

        // Message 1 is shifted to the carry bits
        self.unchecked_scalar_mul_assign(ct_left, modulus as u8)?;

        // Message 2 is placed in the message bits
        self.unchecked_add_assign(ct_left, ct_right)?;

        // Compute the PBS
        self.keyswitch_programmable_bootstrap_assign(server_key, ct_left, acc)?;

        Ok(())
    }

    pub(crate) fn generate_accumulator_bivariate<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertextOwned<u64>>
    where
        F: Fn(u64, u64) -> u64,
    {
        Self::generate_accumulator_bivariate_with_engine(server_key, f)
    }

    pub(crate) fn unchecked_functional_bivariate_pbs<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> EngineResult<Ciphertext>
    where
        F: Fn(u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_functional_bivariate_pbs_assign(server_key, &mut ct_res, ct_right, f)?;
        Ok(ct_res)
    }

    pub(crate) fn unchecked_functional_bivariate_pbs_assign<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> EngineResult<()>
    where
        F: Fn(u64) -> u64,
    {
        let modulus = (ct_right.degree.0 + 1) as u64;

        // Message 1 is shifted to the carry bits
        self.unchecked_scalar_mul_assign(ct_left, modulus as u8)?;

        // Message 2 is placed in the message bits
        self.unchecked_add_assign(ct_left, ct_right)?;

        // Generate the accumulator for the function
        let acc = self.generate_accumulator(server_key, f)?;

        // Compute the PBS
        self.keyswitch_programmable_bootstrap_assign(server_key, ct_left, &acc)?;
        Ok(())
    }

    // Those are currently not used in shortint, we therefore disable the warning when not compiling
    // the C API
    #[cfg_attr(not(feature = "__c_api"), allow(dead_code))]
    pub(crate) fn smart_bivariate_pbs(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<Ciphertext> {
        let mut ct_res = ct_left.clone();
        self.smart_bivariate_pbs_assign(server_key, &mut ct_res, ct_right, acc)?;
        Ok(ct_res)
    }

    #[cfg_attr(not(feature = "__c_api"), allow(dead_code))]
    pub(crate) fn smart_bivariate_pbs_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        self.unchecked_bivariate_pbs_assign(server_key, ct_left, ct_right, acc)
    }

    #[cfg_attr(not(feature = "__c_api"), allow(dead_code))]
    pub(crate) fn unchecked_bivariate_pbs_assign(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;

        // Message 1 is shifted to the carry bits
        self.unchecked_scalar_mul_assign(ct_left, modulus as u8)?;

        // Message 2 is placed in the message bits
        self.unchecked_add_assign(ct_left, ct_right)?;

        // Compute the PBS
        self.keyswitch_programmable_bootstrap_assign(server_key, ct_left, acc)?;
        Ok(())
    }

    pub(crate) fn carry_extract_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let accumulator = self.generate_accumulator(server_key, |x| x / modulus)?;

        self.keyswitch_programmable_bootstrap_assign(server_key, ct, &accumulator)?;

        // The degree of the carry
        ct.degree = Degree(min(modulus - 1, ct.degree.0 as u64 / modulus) as usize);
        Ok(())
    }

    pub(crate) fn carry_extract(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.carry_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    pub(crate) fn message_extract_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let acc = self.generate_accumulator(server_key, |x| x % modulus)?;

        self.keyswitch_programmable_bootstrap_assign(server_key, ct, &acc)?;

        ct.degree = Degree(ct.message_modulus.0 - 1);
        Ok(())
    }

    pub(crate) fn message_extract(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.message_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    // Impossible to call the assign function in this case
    pub(crate) fn create_trivial(
        &mut self,
        server_key: &ServerKey,
        value: u8,
    ) -> EngineResult<Ciphertext> {
        let lwe_size = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size();

        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(lwe_size, encoded);

        let degree = Degree(modular_value);

        Ok(Ciphertext {
            ct,
            degree,
            message_modulus: server_key.message_modulus,
            carry_modulus: server_key.carry_modulus,
        })
    }

    pub(crate) fn create_trivial_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        value: u8,
    ) -> EngineResult<()> {
        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        trivially_encrypt_lwe_ciphertext(&mut ct.ct, encoded);

        ct.degree = Degree(modular_value);
        Ok(())
    }
}
