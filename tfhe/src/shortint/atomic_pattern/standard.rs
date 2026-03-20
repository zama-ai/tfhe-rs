use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::Versionize;

use super::{
    apply_ms_blind_rotate, apply_programmable_bootstrap, AtomicPattern, AtomicPatternKind,
    AtomicPatternMut,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    allocate_and_generate_new_lwe_keyswitch_key, extract_lwe_sample_from_glwe_ciphertext,
    keyswitch_lwe_ciphertext, LweCiphertext, LweCiphertextOwned, LweDimension,
    LweKeyswitchKeyOwned, MonomialDegree, MsDecompressionType,
};
use crate::shortint::backward_compatibility::atomic_pattern::StandardAtomicPatternServerKeyVersions;
use crate::shortint::ciphertext::{CompressedModulusSwitchedCiphertext, Degree, NoiseLevel};
use crate::shortint::client_key::atomic_pattern::StandardAtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::oprf::generate_pseudo_random_from_pbs;
use crate::shortint::server_key::{
    decompress_and_apply_lookup_table, switch_modulus_and_compress, LookupTableOwned,
    LookupTableSize, ManyLookupTableOwned, ShortintBootstrappingKey,
};
use crate::shortint::{
    Ciphertext, CiphertextModulus, EncryptionKeyChoice, PBSOrder, PBSParameters,
};

/// The definition of the server key elements used in the [`Standard`](AtomicPatternKind::Standard)
/// atomic pattern
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(StandardAtomicPatternServerKeyVersions)]
pub struct StandardAtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey<u64>,
    pub pbs_order: PBSOrder,
}

impl ParameterSetConformant for StandardAtomicPatternServerKey {
    type ParameterSet = PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        let pbs_conformance_params = parameter_set.into();

        let pbs_key_ok = bootstrapping_key.is_conformant(&pbs_conformance_params);

        let ks_conformance_params = parameter_set.into();

        let ks_key_ok = key_switching_key.is_conformant(&ks_conformance_params);

        let params_pbs_order: PBSOrder = parameter_set.encryption_key_choice().into();
        let pbs_order_ok = *pbs_order == params_pbs_order;

        pbs_key_ok && ks_key_ok && pbs_order_ok
    }
}

impl StandardAtomicPatternServerKey {
    pub fn new(cks: &StandardAtomicPatternClientKey, engine: &mut ShortintEngine) -> Self {
        let params = &cks.parameters;

        let in_key = &cks.small_lwe_secret_key();

        let out_key = &cks.glwe_secret_key;

        let bootstrapping_key_base = engine.new_bootstrapping_key(*params, in_key, out_key);

        // Creation of the key switching key
        let key_switching_key = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.large_lwe_secret_key(),
            &cks.small_lwe_secret_key(),
            params.ks_base_log(),
            params.ks_level(),
            params.lwe_noise_distribution(),
            params.ciphertext_modulus(),
            &mut engine.encryption_generator,
        );

        Self::from_raw_parts(
            key_switching_key,
            bootstrapping_key_base,
            params.encryption_key_choice().into(),
        )
    }

    pub fn from_raw_parts(
        key_switching_key: LweKeyswitchKeyOwned<u64>,
        bootstrapping_key: ShortintBootstrappingKey<u64>,
        pbs_order: PBSOrder,
    ) -> Self {
        assert_eq!(
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension(),
            "Mismatch between the input LweKeyswitchKey LweDimension ({:?}) \
            and the ShortintBootstrappingKey output LweDimension ({:?})",
            key_switching_key.input_key_lwe_dimension(),
            bootstrapping_key.output_lwe_dimension()
        );

        assert_eq!(
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension(),
            "Mismatch between the output LweKeyswitchKey LweDimension ({:?}) \
            and the ShortintBootstrappingKey input LweDimension ({:?})",
            key_switching_key.output_key_lwe_dimension(),
            bootstrapping_key.input_lwe_dimension()
        );

        Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        }
    }

    pub fn intermediate_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                self.ciphertext_lwe_dimension_for_key(EncryptionKeyChoice::Small)
            }
            PBSOrder::BootstrapKeyswitch => {
                self.ciphertext_lwe_dimension_for_key(EncryptionKeyChoice::Big)
            }
        }
    }
}

impl AtomicPattern for StandardAtomicPatternServerKey {
    fn ciphertext_lwe_dimension_for_key(&self, key_choice: EncryptionKeyChoice) -> LweDimension {
        match key_choice {
            EncryptionKeyChoice::Big => self.bootstrapping_key.output_lwe_dimension(),
            EncryptionKeyChoice::Small => self.bootstrapping_key.input_lwe_dimension(),
        }
    }

    fn ciphertext_modulus_for_key(&self, _key_choice: EncryptionKeyChoice) -> CiphertextModulus {
        // Both keys use the same modulus
        self.key_switching_key.ciphertext_modulus()
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        match &self.bootstrapping_key {
            ShortintBootstrappingKey::Classic { .. } => MsDecompressionType::ClassicPbs,
            ShortintBootstrappingKey::MultiBit { fourier_bsk, .. } => {
                MsDecompressionType::MultiBitPbs(fourier_bsk.grouping_factor())
            }
        }
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffer, buffers) =
                engine.get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

            match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => {
                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ct.ct,
                        &mut ciphertext_buffer,
                    );

                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ciphertext_buffer,
                        &mut ct.ct,
                        &acc.acc,
                        buffers,
                    );
                }
                PBSOrder::BootstrapKeyswitch => {
                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ct.ct,
                        &mut ciphertext_buffer,
                        &acc.acc,
                        buffers,
                    );

                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ciphertext_buffer,
                        &mut ct.ct,
                    );
                }
            }
        });
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        acc: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.keyswitch_programmable_bootstrap_many_lut(ct, acc),
            PBSOrder::BootstrapKeyswitch => self.programmable_bootstrap_keyswitch_many_lut(ct, acc),
        }
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        LookupTableSize::new(
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
        )
    }

    fn kind(&self) -> AtomicPatternKind {
        AtomicPatternKind::Standard(self.pbs_order)
    }

    fn deterministic_execution(&self) -> bool {
        self.bootstrapping_key.deterministic_pbs_execution()
    }

    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> (LweCiphertextOwned<u64>, Degree) {
        let (ct, degree) = generate_pseudo_random_from_pbs(
            &self.bootstrapping_key,
            seed,
            random_bits_count,
            full_bits_count,
            self.ciphertext_modulus(),
        );

        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => (ct, degree),
            PBSOrder::BootstrapKeyswitch => {
                let mut ct_ksed = LweCiphertext::new(
                    0,
                    self.bootstrapping_key.input_lwe_dimension().to_lwe_size(),
                    self.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(&self.key_switching_key, &ct, &mut ct_ksed);

                (ct_ksed, degree)
            }
        }
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        let compressed_modulus_switched_lwe_ciphertext =
            ShortintEngine::with_thread_local_mut(|engine| {
                let (mut ciphertext_buffer, _) = engine
                    .get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

                let input_ct = match self.pbs_order {
                    PBSOrder::KeyswitchBootstrap => {
                        keyswitch_lwe_ciphertext(
                            &self.key_switching_key,
                            &ct.ct,
                            &mut ciphertext_buffer,
                        );
                        ciphertext_buffer.as_view()
                    }
                    PBSOrder::BootstrapKeyswitch => ct.ct.as_view(),
                };

                switch_modulus_and_compress(input_ct, &self.bootstrapping_key)
            });

        CompressedModulusSwitchedCiphertext {
            compressed_modulus_switched_lwe_ciphertext,
            degree: ct.degree,
            message_modulus: ct.message_modulus,
            carry_modulus: ct.carry_modulus,
            atomic_pattern: ct.atomic_pattern,
        }
    }

    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext {
        let mut output = LweCiphertext::new(
            0,
            self.ciphertext_lwe_dimension().to_lwe_size(),
            self.ciphertext_modulus(),
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffer, buffers) =
                engine.get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

            match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => {
                    decompress_and_apply_lookup_table(
                        compressed_ct,
                        &lut.acc,
                        &self.bootstrapping_key,
                        &mut output.as_mut_view(),
                        buffers,
                    );
                }
                PBSOrder::BootstrapKeyswitch => {
                    decompress_and_apply_lookup_table(
                        compressed_ct,
                        &lut.acc,
                        &self.bootstrapping_key,
                        &mut ciphertext_buffer,
                        buffers,
                    );

                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ciphertext_buffer,
                        &mut output,
                    );
                }
            }
        });

        Ciphertext::new(
            output,
            lut.degree,
            NoiseLevel::NOMINAL,
            compressed_ct.message_modulus,
            compressed_ct.carry_modulus,
            compressed_ct.atomic_pattern,
        )
    }
}

impl AtomicPatternMut for StandardAtomicPatternServerKey {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution)
    }
}

impl StandardAtomicPatternServerKey {
    pub(crate) fn keyswitch_programmable_bootstrap_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffer, buffers) =
                engine.get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

            // Compute a key switch
            keyswitch_lwe_ciphertext(&self.key_switching_key, &ct.ct, &mut ciphertext_buffer);

            apply_ms_blind_rotate(
                &self.bootstrapping_key,
                &ciphertext_buffer.as_view(),
                &mut acc,
                buffers,
            );
        });

        // The accumulator has been rotated, we can now proceed with the various sample extractions
        let function_count = lut.function_count();
        let mut outputs = Vec::with_capacity(function_count);

        for (fn_idx, output_degree) in lut.per_function_output_degree.iter().enumerate() {
            let monomial_degree = MonomialDegree(fn_idx * lut.sample_extraction_stride);
            let mut output_shortint_ct = ct.clone();

            extract_lwe_sample_from_glwe_ciphertext(
                &acc,
                &mut output_shortint_ct.ct,
                monomial_degree,
            );

            output_shortint_ct.degree = *output_degree;
            output_shortint_ct.set_noise_level_to_nominal();
            outputs.push(output_shortint_ct);
        }

        outputs
    }

    pub(crate) fn programmable_bootstrap_keyswitch_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let buffers = engine.get_computation_buffers();

            apply_ms_blind_rotate(&self.bootstrapping_key, &ct.ct, &mut acc, buffers);
        });

        // The accumulator has been rotated, we can now proceed with the various sample extractions
        let function_count = lut.function_count();
        let mut outputs = Vec::with_capacity(function_count);

        let mut tmp_lwe_ciphertext = LweCiphertext::new(
            0u64,
            self.key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            self.key_switching_key.ciphertext_modulus(),
        );

        for (fn_idx, output_degree) in lut.per_function_output_degree.iter().enumerate() {
            let monomial_degree = MonomialDegree(fn_idx * lut.sample_extraction_stride);
            extract_lwe_sample_from_glwe_ciphertext(&acc, &mut tmp_lwe_ciphertext, monomial_degree);

            let mut output_shortint_ct = ct.clone();

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &tmp_lwe_ciphertext,
                &mut output_shortint_ct.ct,
            );

            output_shortint_ct.degree = *output_degree;
            output_shortint_ct.set_noise_level_to_nominal();
            outputs.push(output_shortint_ct);
        }

        outputs
    }
}
