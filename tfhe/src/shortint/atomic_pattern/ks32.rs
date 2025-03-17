use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::NotVersioned;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext_with_scalar_change,
    CiphertextModulus as CoreCiphertextModulus, LweCiphertext, LweCiphertextOwned, LweDimension,
    LweKeyswitchKeyConformanceParams, LweKeyswitchKeyOwned, MonomialDegree, MsDecompressionType,
};
use crate::shortint::ciphertext::{CompressedModulusSwitchedCiphertext, NoiseLevel};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::oprf::generate_pseudo_random_from_pbs;
use crate::shortint::server_key::{
    apply_blind_rotate_no_ms_noise_reduction, decompress_and_apply_lookup_table,
    switch_modulus_and_compress, LookupTableOwned, LookupTableSize, ManyLookupTableOwned,
    PBSConformanceParams, ShortintBootstrappingKey,
};
use crate::shortint::{Ciphertext, CiphertextModulus, PBSParameters};

use super::{
    apply_programmable_bootstrap, AtomicPattern, AtomicPatternMutOperations,
    AtomicPatternOperations,
};

/// The definition of the server key elements used in the [`AtomicPattern::KeySwitch32`] atomic
/// pattern
///
/// [`Classical`]: AtomicPattern::KeySwitch32
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)] // TODO: Versionize
pub struct KS32AtomicPatternServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u32>,
    pub bootstrapping_key: ShortintBootstrappingKey<u32>,
}

impl ParameterSetConformant for KS32AtomicPatternServerKey {
    type ParameterSet = PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
        } = self;

        let params: PBSConformanceParams = parameter_set.into();

        let pbs_key_ok = bootstrapping_key.is_conformant(&params);

        let param: LweKeyswitchKeyConformanceParams = parameter_set.into();

        let ks_key_ok = key_switching_key.is_conformant(&param);

        pbs_key_ok && ks_key_ok
    }
}

impl KS32AtomicPatternServerKey {
    pub fn from_raw_parts(
        key_switching_key: LweKeyswitchKeyOwned<u32>,
        bootstrapping_key: ShortintBootstrappingKey<u32>,
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
        }
    }

    pub fn intermediate_lwe_dimension(&self) -> LweDimension {
        self.key_switching_key.output_key_lwe_dimension()
    }
}

impl AtomicPatternOperations for KS32AtomicPatternServerKey {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        self.key_switching_key.input_key_lwe_dimension()
    }

    fn ciphertext_modulus(&self) -> CiphertextModulus {
        self.key_switching_key
            .ciphertext_modulus()
            .try_to()
            // CiphertextModulus::try_to fails if target scalar is smaller than the input one, we
            // know that it is not the case so it is ok to unwrap
            .unwrap()
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
                CoreCiphertextModulus::new_native(),
            );

            keyswitch_lwe_ciphertext_with_scalar_change(
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
        });
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        acc: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        self.keyswitch_programmable_bootstrap_many_lut(ct, acc)
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        LookupTableSize::new(
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
        )
    }

    fn atomic_pattern(&self) -> AtomicPattern {
        AtomicPattern::KeySwitch32
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
        generate_pseudo_random_from_pbs(
            &self.bootstrapping_key,
            seed,
            random_bits_count,
            full_bits_count,
            self.ciphertext_modulus(),
        )
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        let compressed_modulus_switched_lwe_ciphertext =
            ShortintEngine::with_thread_local_mut(|engine| {
                let (mut ciphertext_buffer, _) = engine.get_buffers(
                    self.intermediate_lwe_dimension(),
                    CoreCiphertextModulus::new_native(),
                );

                keyswitch_lwe_ciphertext_with_scalar_change(
                    &self.key_switching_key,
                    &ct.ct,
                    &mut ciphertext_buffer,
                );
                switch_modulus_and_compress(ciphertext_buffer.as_view(), &self.bootstrapping_key)
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

            decompress_and_apply_lookup_table(
                compressed_ct,
                &lut.acc,
                &self.bootstrapping_key,
                &mut ciphertext_buffer,
                buffers,
            );

            output
                .as_mut()
                .copy_from_slice(ciphertext_buffer.into_container())
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
        let mut after_ks_ct = LweCiphertext::new(
            0,
            self.key_switching_key.output_lwe_size(),
            self.key_switching_key.ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext_with_scalar_change(
            &self.key_switching_key,
            &ct.ct,
            &mut after_ks_ct,
        );

        let mut scalar_64_ct = LweCiphertext::new(
            0u64,
            self.key_switching_key.output_lwe_size(),
            self.key_switching_key
                .ciphertext_modulus()
                .try_to()
                .unwrap(), // Ok to unwrap because we go from 32 to 64b
        );

        for (coeff64, coeff32) in scalar_64_ct
            .as_mut()
            .iter_mut()
            .zip(after_ks_ct.as_ref().iter())
        {
            *coeff64 = *coeff32 as u64;
        }

        scalar_64_ct
    }
}

impl AtomicPatternMutOperations for KS32AtomicPatternServerKey {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution)
    }
}

impl KS32AtomicPatternServerKey {
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
                CoreCiphertextModulus::new_native(),
            );

            // Compute a key switch
            keyswitch_lwe_ciphertext_with_scalar_change(
                &self.key_switching_key,
                &ct.ct,
                &mut ciphertext_buffer,
            );

            apply_blind_rotate_no_ms_noise_reduction(
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
}
