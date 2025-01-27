use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext, LweCiphertext,
    LweKeyswitchKeyOwned, MonomialDegree, UnsignedInteger,
};

use super::engine::ShortintEngine;
use super::prelude::LweDimension;
use super::server_key::{
    apply_blind_rotate, apply_programmable_bootstrap, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned, ShortintBootstrappingKey,
};
use super::{Ciphertext, PBSOrder};

// TODO: doc comment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, NotVersioned)]
pub enum AtomicPattern {
    Classical(PBSOrder),
}

pub trait AtomicPatternOperations {
    fn ciphertext_lwe_dimension(&self) -> LweDimension;

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned);

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext>;

    fn lookup_table_size(&self) -> LookupTableSize;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)] // TODO: Versionize
pub struct ClassicalAtomicPatternServerKey<KeyswitchScalar>
where
    KeyswitchScalar: UnsignedInteger,
{
    pub key_switching_key: LweKeyswitchKeyOwned<KeyswitchScalar>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    pub pbs_order: PBSOrder,
}

impl<KeyswitchScalar: UnsignedInteger> ClassicalAtomicPatternServerKey<KeyswitchScalar> {
    fn intermediate_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.output_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.input_key_lwe_dimension(),
        }
    }
}

impl AtomicPatternOperations for ClassicalAtomicPatternServerKey<u64> {
    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffer, buffers): (LweCiphertext<Vec<u64>>, _) = todo!();
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

    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        }
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        LookupTableSize::new(
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
        )
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
}

impl ClassicalAtomicPatternServerKey<u64> {
    pub(crate) fn keyswitch_programmable_bootstrap_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (mut ciphertext_buffer, buffers): (LweCiphertext<Vec<u64>>, _) = todo!();

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)] // TODO: Versionize
pub enum ServerKeyAtomicPattern {
    Classical(ClassicalAtomicPatternServerKey<u64>),
    KeySwitch32(ClassicalAtomicPatternServerKey<u32>),
}

impl AtomicPatternOperations for ServerKeyAtomicPattern {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classical(ap) => ap.ciphertext_lwe_dimension(),
            Self::KeySwitch32(_) => todo!(),
        }
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        match self {
            Self::Classical(ap) => ap.apply_lookup_table_assign(ct, acc),
            Self::KeySwitch32(_) => todo!(),
        }
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        match self {
            Self::Classical(ap) => ap.apply_many_lookup_table(ct, lut),
            Self::KeySwitch32(_) => todo!(),
        }
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        match self {
            Self::Classical(ap) => ap.lookup_table_size(),
            Self::KeySwitch32(_) => todo!(),
        }
    }
}

impl From<&ServerKeyAtomicPattern> for AtomicPattern {
    fn from(value: &ServerKeyAtomicPattern) -> Self {
        match value {
            ServerKeyAtomicPattern::Classical(ap) => Self::Classical(ap.pbs_order),
            ServerKeyAtomicPattern::KeySwitch32(_) => todo!(),
        }
    }
}
