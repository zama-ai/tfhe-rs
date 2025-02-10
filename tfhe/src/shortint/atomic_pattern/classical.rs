use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::NotVersioned;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext,
    multi_bit_deterministic_blind_rotate_assign, CompressedModulusSwitchedLweCiphertext,
    CompressedModulusSwitchedMultiBitLweCiphertext, GlweCiphertext, LweCiphertext,
    LweCiphertextOwned, LweDimension, LweKeyswitchKeyConformanceParams, LweKeyswitchKeyOwned,
    MonomialDegree, MsDecompressionType,
};
use crate::shortint::ciphertext::{
    CompressedModulusSwitchedCiphertext, InternalCompressedModulusSwitchedCiphertext, NoiseLevel,
};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::oprf::generate_pseudo_random_from_pbs;
use crate::shortint::server_key::{
    apply_modulus_switch_noise_reduction, apply_programmable_bootstrap_no_ms_noise_reduction,
    LookupTableOwned, LookupTableSize, ManyLookupTableOwned, PBSConformanceParams,
    ShortintBootstrappingKey,
};
use crate::shortint::{
    Ciphertext, CiphertextModulus, EncryptionKeyChoice, PBSOrder, PBSParameters,
};

use super::{
    apply_blind_rotate, apply_programmable_bootstrap, AtomicPattern, AtomicPatternMutOperations,
    AtomicPatternOperations,
};

/// The definition of the server key elements used in the [`Classical`] atomic pattern
///
/// [`Classical`]: AtomicPattern::Classical
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)] // TODO: Versionize
pub struct ClassicalAtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    pub pbs_order: PBSOrder,
}

impl ParameterSetConformant for ClassicalAtomicPatternServerKey {
    type ParameterSet = PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        let params: PBSConformanceParams = parameter_set.into();

        let pbs_key_ok = bootstrapping_key.is_conformant(&params);

        let param: LweKeyswitchKeyConformanceParams = parameter_set.into();

        let ks_key_ok = key_switching_key.is_conformant(&param);

        let pbs_order_ok = matches!(
            (*pbs_order, parameter_set.encryption_key_choice()),
            (PBSOrder::KeyswitchBootstrap, EncryptionKeyChoice::Big)
                | (PBSOrder::BootstrapKeyswitch, EncryptionKeyChoice::Small)
        );

        pbs_key_ok && ks_key_ok && pbs_order_ok
    }
}

impl ClassicalAtomicPatternServerKey {
    pub fn from_raw_parts(
        key_switching_key: LweKeyswitchKeyOwned<u64>,
        bootstrapping_key: ShortintBootstrappingKey,
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
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.output_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.input_key_lwe_dimension(),
        }
    }
}

impl AtomicPatternOperations for ClassicalAtomicPatternServerKey {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        }
    }

    fn ciphertext_modulus(&self) -> CiphertextModulus {
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
            let (mut ciphertext_buffer, buffers) = engine.get_buffers(
                self.intermediate_lwe_dimension(),
                CiphertextModulus::new_native(),
            );

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

    fn atomic_pattern(&self) -> AtomicPattern {
        AtomicPattern::Classical(self.pbs_order)
    }

    fn deterministic_execution(&self) -> bool {
        self.bootstrapping_key.deterministic_pbs_execution()
    }

    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> LweCiphertextOwned<u64> {
        let ct = generate_pseudo_random_from_pbs(
            &self.bootstrapping_key,
            seed,
            random_bits_count,
            full_bits_count,
            self.ciphertext_modulus(),
        );

        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => ct,
            PBSOrder::BootstrapKeyswitch => {
                let mut ct_ksed = LweCiphertext::new(
                    0,
                    self.bootstrapping_key.input_lwe_dimension().to_lwe_size(),
                    self.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(&self.key_switching_key, &ct, &mut ct_ksed);

                ct_ksed
            }
        }
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        let compressed_modulus_switched_lwe_ciphertext =
            ShortintEngine::with_thread_local_mut(|engine| {
                let (mut ciphertext_buffer, _) = engine
                    .get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

                match self.pbs_order {
                    PBSOrder::KeyswitchBootstrap => {
                        keyswitch_lwe_ciphertext(
                            &self.key_switching_key,
                            &ct.ct,
                            &mut ciphertext_buffer,
                        );
                    }
                    PBSOrder::BootstrapKeyswitch => {
                        ciphertext_buffer.as_mut().copy_from_slice(ct.ct.as_ref())
                    }
                }

                match &self.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key,
                    } => {
                        let log_modulus =
                            bsk.polynomial_size().to_blind_rotation_input_modulus_log();

                        let input_improved_before_ms;

                        // The solution suggested by clippy does not work because of the capture of
                        // `input_improved_before_ms`
                        #[allow(clippy::option_if_let_else)]
                        let input_modulus_switch = if let Some(modulus_switch_noise_reduction_key) =
                            modulus_switch_noise_reduction_key
                        {
                            input_improved_before_ms = apply_modulus_switch_noise_reduction(
                                modulus_switch_noise_reduction_key,
                                log_modulus,
                                &ciphertext_buffer,
                            );

                            input_improved_before_ms.as_view()
                        } else {
                            ciphertext_buffer.as_view()
                        };

                        InternalCompressedModulusSwitchedCiphertext::Classic(
                            CompressedModulusSwitchedLweCiphertext::compress(
                                &input_modulus_switch,
                                log_modulus,
                            ),
                        )
                    }
                    ShortintBootstrappingKey::MultiBit { fourier_bsk, .. } => {
                        InternalCompressedModulusSwitchedCiphertext::MultiBit(
                            CompressedModulusSwitchedMultiBitLweCiphertext::compress(
                                &ciphertext_buffer,
                                self.bootstrapping_key
                                    .polynomial_size()
                                    .to_blind_rotation_input_modulus_log(),
                                fourier_bsk.grouping_factor(),
                            ),
                        )
                    }
                }
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
        let mut output = LweCiphertext::from_container(
            vec![0; self.ciphertext_lwe_dimension().to_lwe_size().0],
            self.ciphertext_modulus(),
        );

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffer, buffers) =
                engine.get_buffers(self.intermediate_lwe_dimension(), self.ciphertext_modulus());

            match &self.bootstrapping_key {
                ShortintBootstrappingKey::Classic { .. } => {
                    let ct = match &compressed_ct.compressed_modulus_switched_lwe_ciphertext {
                        InternalCompressedModulusSwitchedCiphertext::Classic(a) => a.extract(),
                        InternalCompressedModulusSwitchedCiphertext::MultiBit(_) => {
                            panic!("Compression was done targeting a MultiBit bootstrap decompression, cannot decompress with a Classic bootstrapping key")
                        }
                    };
                    apply_programmable_bootstrap_no_ms_noise_reduction(
                        &self.bootstrapping_key,
                        &ct,
                        &mut ciphertext_buffer,
                        &lut.acc,
                        buffers,
                    );
                }
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution: _,
                } => {
                    let ct = match &compressed_ct.compressed_modulus_switched_lwe_ciphertext {
                        InternalCompressedModulusSwitchedCiphertext::MultiBit(a) => a.extract(),
                        InternalCompressedModulusSwitchedCiphertext::Classic(_) => {
                            panic!("Compression was done targeting a Classic bootstrap decompression, cannot decompress with a MultiBit bootstrapping key")
                        }
                    };

                    let mut local_accumulator = GlweCiphertext::new(
                        0,
                        lut.acc.glwe_size(),
                        lut.acc.polynomial_size(),
                        lut.acc.ciphertext_modulus(),
                    );
                    local_accumulator.as_mut().copy_from_slice(lut.acc.as_ref());

                    multi_bit_deterministic_blind_rotate_assign(
                        &ct,
                        &mut local_accumulator,
                        fourier_bsk,
                        *thread_count,
                    );

                    extract_lwe_sample_from_glwe_ciphertext(
                        &local_accumulator,
                        &mut ciphertext_buffer,
                        MonomialDegree(0),
                    );
                }
            }

            match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => output
                    .as_mut()
                    .copy_from_slice(ciphertext_buffer.into_container()),
                PBSOrder::BootstrapKeyswitch => {
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

    fn prepare_for_noise_squashing(&self, ct: &Ciphertext) -> LweCiphertextOwned<u64> {
        match self.pbs_order {
            // Under the big key, first need to keyswitch
            PBSOrder::KeyswitchBootstrap => {
                let mut after_ks_ct = LweCiphertext::new(
                    0u64,
                    self.key_switching_key.output_lwe_size(),
                    self.key_switching_key.ciphertext_modulus(),
                );

                keyswitch_lwe_ciphertext(&self.key_switching_key, &ct.ct, &mut after_ks_ct);
                after_ks_ct
            }
            // Under the small key, no need to keyswitch
            PBSOrder::BootstrapKeyswitch => ct.ct.clone(),
        }
    }
}

impl AtomicPatternMutOperations for ClassicalAtomicPatternServerKey {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution)
    }
}

impl ClassicalAtomicPatternServerKey {
    pub(crate) fn keyswitch_programmable_bootstrap_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (mut ciphertext_buffer, buffers) = engine.get_buffers(
                self.intermediate_lwe_dimension(),
                CiphertextModulus::new_native(),
            );

            // Compute a key switch
            keyswitch_lwe_ciphertext(&self.key_switching_key, &ct.ct, &mut ciphertext_buffer);

            apply_blind_rotate(
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

            apply_blind_rotate(&self.bootstrapping_key, &ct.ct, &mut acc, buffers);
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
            outputs.push(output_shortint_ct);
        }

        outputs
    }
}
