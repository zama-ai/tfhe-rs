use super::ShortintEngine;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::math::fft::Fft;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::EngineResult;
use crate::shortint::parameters::MessageModulus;
use crate::shortint::server_key::{BivariateLookupTableOwned, LookupTableOwned, MaxDegree};
use crate::shortint::{
    CiphertextBase, CiphertextBig, CiphertextSmall, ClientKey, CompressedServerKey, PBSOrder,
    PBSOrderMarker, ServerKey,
};

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

    pub(crate) fn new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> EngineResult<ServerKey> {
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.small_lwe_secret_key,
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
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
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
            &cks.large_lwe_secret_key,
            &cks.small_lwe_secret_key,
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

    pub(crate) fn new_compressed_server_key(
        &mut self,
        cks: &ClientKey,
    ) -> EngineResult<CompressedServerKey> {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree(max_value);
        self.new_compressed_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn new_compressed_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> EngineResult<CompressedServerKey> {
        #[cfg(not(feature = "__wasm_api"))]
        let bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
            &cks.small_lwe_secret_key,
            &cks.glwe_secret_key,
            cks.parameters.pbs_base_log,
            cks.parameters.pbs_level,
            cks.parameters.glwe_modular_std_dev,
            &mut self.seeder,
        );

        #[cfg(feature = "__wasm_api")]
        let bootstrapping_key = allocate_and_generate_new_seeded_lwe_bootstrap_key(
            &cks.small_lwe_secret_key,
            &cks.glwe_secret_key,
            cks.parameters.pbs_base_log,
            cks.parameters.pbs_level,
            cks.parameters.glwe_modular_std_dev,
            &mut self.seeder,
        );

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_seeded_lwe_keyswitch_key(
            &cks.large_lwe_secret_key,
            &cks.small_lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            &mut self.seeder,
        );

        // Pack the keys in the server key set:
        Ok(CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus: cks.parameters.message_modulus,
            carry_modulus: cks.parameters.carry_modulus,
            max_degree,
        })
    }

    pub(crate) fn generate_accumulator<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<LookupTableOwned>
    where
        F: Fn(u64) -> u64,
    {
        Self::generate_accumulator_with_engine(server_key, f)
    }

    pub(crate) fn keyswitch_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBig,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (mut ciphertext_buffers, buffers) =
            self.get_carry_clearing_accumulator_and_buffers(server_key);

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
            &ciphertext_buffers.accumulator.acc,
            fourier_bsk,
            fft,
            stack,
        );

        ct.degree = ciphertext_buffers.accumulator.degree;

        Ok(())
    }

    pub(crate) fn clear_carry<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut ct_in = ct.clone();
        self.clear_carry_assign(server_key, &mut ct_in)?;
        Ok(ct_in)
    }

    pub(crate) fn clear_carry_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        match OpOrder::pbs_order() {
            PBSOrder::KeyswitchBootstrap => {
                let ct = unsafe { std::mem::transmute(ct) };
                self.keyswitch_bootstrap_assign(server_key, ct)?;
            }
            PBSOrder::BootstrapKeyswitch => {
                let ct = unsafe { std::mem::transmute(ct) };
                self.bootstrap_keyswitch_assign(server_key, ct)?;
            }
        }
        Ok(())
    }

    pub(crate) fn keyswitch_programmable_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBig,
        acc: &LookupTableOwned,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (mut ciphertext_buffers, buffers) =
            self.get_carry_clearing_accumulator_and_buffers(server_key);

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

        ct.degree = acc.degree;

        Ok(())
    }

    pub(crate) fn unchecked_apply_lookup_table_bivariate<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
        acc: &BivariateLookupTableOwned,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut ct_res = ct_left.clone();
        self.unchecked_apply_lookup_table_bivariate_assign(server_key, &mut ct_res, ct_right, acc)?;
        Ok(ct_res)
    }

    pub(crate) fn unchecked_apply_lookup_table_bivariate_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
        acc: &BivariateLookupTableOwned,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        assert!(modulus <= acc.ct_right_modulus.0 as u64);

        // Message 1 is shifted
        self.unchecked_scalar_mul_assign(ct_left, acc.ct_right_modulus.0 as u8)?;

        self.unchecked_add_assign(ct_left, ct_right)?;

        // Compute the PBS
        self.apply_lookup_table_assign(server_key, ct_left, &acc.acc)?;

        Ok(())
    }

    pub(crate) fn generate_accumulator_bivariate_with_factor<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
        left_message_scaling: MessageModulus,
    ) -> EngineResult<BivariateLookupTableOwned>
    where
        F: Fn(u64, u64) -> u64,
    {
        Self::generate_accumulator_bivariate_with_engine(server_key, f, left_message_scaling)
    }

    pub(crate) fn generate_accumulator_bivariate<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<BivariateLookupTableOwned>
    where
        F: Fn(u64, u64) -> u64,
    {
        // We use the message_modulus as the multiplying factor as its the most general one.
        // It makes it compatible with any pair of ciphertext which have empty carries,
        // and carries can be emptied with `message_extract`
        self.generate_accumulator_bivariate_with_factor(server_key, f, server_key.message_modulus)
    }

    pub(crate) fn unchecked_evaluate_bivariate_function<F, OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
        f: F,
    ) -> EngineResult<CiphertextBase<OpOrder>>
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_evaluate_bivariate_function_assign(server_key, &mut ct_res, ct_right, f)?;
        Ok(ct_res)
    }

    pub(crate) fn unchecked_evaluate_bivariate_function_assign<OpOrder: PBSOrderMarker, F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
        f: F,
    ) -> EngineResult<()>
    where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the accumulator for the function
        let factor = MessageModulus(ct_right.degree.0 + 1);
        let acc = self.generate_accumulator_bivariate_with_factor(server_key, f, factor)?;

        self.unchecked_apply_lookup_table_bivariate_assign(server_key, ct_left, ct_right, &acc)?;
        Ok(())
    }

    pub(crate) fn smart_evaluate_bivariate_function<OpOrder: PBSOrderMarker, F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
        f: F,
    ) -> EngineResult<CiphertextBase<OpOrder>>
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();

        self.smart_evaluate_bivariate_function_assign(server_key, &mut ct_res, ct_right, f)?;
        Ok(ct_res)
    }

    pub(crate) fn smart_evaluate_bivariate_function_assign<OpOrder: PBSOrderMarker, F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
        f: F,
    ) -> EngineResult<()>
    where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the accumulator for the function
        let factor = MessageModulus(ct_right.degree.0 + 1);
        let acc = self.generate_accumulator_bivariate_with_factor(server_key, f, factor)?;

        self.smart_apply_lookup_table_bivariate_assign(server_key, ct_left, ct_right, &acc)?;
        Ok(())
    }

    pub(crate) fn smart_apply_lookup_table_bivariate<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
        acc: &BivariateLookupTableOwned,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut ct_res = ct_left.clone();
        self.smart_apply_lookup_table_bivariate_assign(server_key, &mut ct_res, ct_right, acc)?;
        Ok(ct_res)
    }

    pub(crate) fn smart_apply_lookup_table_bivariate_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
        acc: &BivariateLookupTableOwned,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        self.unchecked_apply_lookup_table_bivariate_assign(server_key, ct_left, ct_right, acc)
    }

    pub(crate) fn programmable_bootstrap_keyswitch_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextSmall,
        acc: &LookupTableOwned,
    ) -> EngineResult<()> {
        let (mut ciphertext_buffers, buffers) =
            self.get_carry_clearing_accumulator_and_buffers(server_key);

        let fourier_bsk = &server_key.bootstrapping_key;

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

        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext_buffers.buffer_lwe_after_pbs,
            &mut ct.ct,
        );

        ct.degree = acc.degree;

        Ok(())
    }

    pub(crate) fn bootstrap_keyswitch_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextSmall,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (mut ciphertext_buffers, buffers) =
            self.get_carry_clearing_accumulator_and_buffers(server_key);

        let fourier_bsk = &server_key.bootstrapping_key;

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
            &ciphertext_buffers.accumulator.acc,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a keyswitch
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext_buffers.buffer_lwe_after_pbs,
            &mut ct.ct,
        );

        ct.degree = ciphertext_buffers.accumulator.degree;

        Ok(())
    }

    pub(crate) fn apply_lookup_table_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        acc: &LookupTableOwned,
    ) -> EngineResult<()> {
        // We know the OpOrder corresponds to the CiphertextBig or CiphertextSmall and the memory
        // layout is the same as the type information is just encoded in a phantom data marker
        match OpOrder::pbs_order() {
            PBSOrder::KeyswitchBootstrap => {
                let ct = unsafe { std::mem::transmute(ct) };
                // This updates the ciphertext degree
                self.keyswitch_programmable_bootstrap_assign(server_key, ct, acc)?;
            }
            PBSOrder::BootstrapKeyswitch => {
                let ct = unsafe { std::mem::transmute(ct) };
                // This updates the ciphertext degree
                self.programmable_bootstrap_keyswitch_assign(server_key, ct, acc)?;
            }
        };

        Ok(())
    }

    pub(crate) fn apply_lookup_table<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
        acc: &LookupTableOwned,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut ct_res = ct.clone();

        self.apply_lookup_table_assign(server_key, &mut ct_res, acc)?;

        Ok(ct_res)
    }

    pub(crate) fn apply_msg_identity_lut_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        // We know the OpOrder corresponds to the CiphertextBig or CiphertextSmall and the memory
        // layout is the same as the type information is just encoded in a phantom data marker
        match OpOrder::pbs_order() {
            PBSOrder::KeyswitchBootstrap => {
                let ct = unsafe { std::mem::transmute(ct) };
                // This updates the ciphertext degree
                self.keyswitch_bootstrap_assign(server_key, ct)?;
            }
            PBSOrder::BootstrapKeyswitch => {
                let ct = unsafe { std::mem::transmute(ct) };
                // This updates the ciphertext degree
                self.bootstrap_keyswitch_assign(server_key, ct)?;
            }
        };

        Ok(())
    }

    pub(crate) fn carry_extract_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let accumulator = self.generate_accumulator(server_key, |x| x / modulus)?;

        self.apply_lookup_table_assign(server_key, ct, &accumulator)?;

        Ok(())
    }

    pub(crate) fn carry_extract<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.carry_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    pub(crate) fn message_extract_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let acc = self.generate_accumulator(server_key, |x| x % modulus)?;

        self.apply_lookup_table_assign(server_key, ct, &acc)?;

        Ok(())
    }

    pub(crate) fn message_extract<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let mut result = ct.clone();
        self.message_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    // Impossible to call the assign function in this case
    pub(crate) fn create_trivial<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        value: u64,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let lwe_size = match OpOrder::pbs_order() {
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

        let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(lwe_size, encoded);

        let degree = Degree(modular_value);

        Ok(CiphertextBase {
            ct,
            degree,
            message_modulus: server_key.message_modulus,
            carry_modulus: server_key.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn create_trivial_assign<OpOrder: PBSOrderMarker>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextBase<OpOrder>,
        value: u64,
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
