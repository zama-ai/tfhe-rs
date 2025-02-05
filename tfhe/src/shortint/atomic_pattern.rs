use serde::{Deserialize, Serialize};
use tfhe_versionable::NotVersioned;

use crate::core_crypto::prelude::{
    extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext,
    KeyswitchKeyConformanceParams, LweCiphertext, LweKeyswitchKeyOwned, MonomialDegree,
    MsDecompressionType, UnsignedInteger,
};
use crate::prelude::ParameterSetConformant;

use super::engine::ShortintEngine;
use super::prelude::LweDimension;
use super::server_key::{
    apply_blind_rotate, apply_programmable_bootstrap, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned, PBSConformanceParameters, ShortintBootstrappingKey,
};
use super::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PBSOrder, PBSParameters,
};

// TODO: doc comment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, NotVersioned)]
pub enum AtomicPattern {
    Classical(PBSOrder),
}

pub trait AtomicPatternOperations {
    fn ciphertext_lwe_dimension(&self) -> LweDimension;

    fn ciphertext_modulus(&self) -> CiphertextModulus;

    fn ciphertext_decompression_method(&self) -> MsDecompressionType;

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned);

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext>;

    fn lookup_table_size(&self) -> LookupTableSize;

    fn atomic_pattern(&self) -> AtomicPattern;

    fn deterministic_execution(&self) -> bool;
}

pub trait AtomicPatternMutOperations {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool);
}

impl<T: AtomicPatternOperations> AtomicPatternOperations for &T {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        (*self).ciphertext_lwe_dimension()
    }

    fn ciphertext_modulus(&self) -> CiphertextModulus {
        (*self).ciphertext_modulus()
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        (*self).ciphertext_decompression_method()
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        (*self).apply_lookup_table_assign(ct, acc)
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        (*self).apply_many_lookup_table(ct, lut)
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        (*self).lookup_table_size()
    }

    fn atomic_pattern(&self) -> AtomicPattern {
        (*self).atomic_pattern()
    }

    fn deterministic_execution(&self) -> bool {
        (*self).deterministic_execution()
    }
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

impl ParameterSetConformant for ClassicalAtomicPatternServerKey<u64> {
    type ParameterSet = PBSParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            pbs_order,
        } = self;

        let params: PBSConformanceParameters = parameter_set.into();

        let pbs_key_ok = bootstrapping_key.is_conformant(&params);

        let param: KeyswitchKeyConformanceParams = parameter_set.into();

        let ks_key_ok = key_switching_key.is_conformant(&param);

        let pbs_order_ok = matches!(
            (*pbs_order, parameter_set.encryption_key_choice()),
            (PBSOrder::KeyswitchBootstrap, EncryptionKeyChoice::Big)
                | (PBSOrder::BootstrapKeyswitch, EncryptionKeyChoice::Small)
        );

        pbs_key_ok && ks_key_ok && pbs_order_ok
    }
}

impl<KeyswitchScalar: UnsignedInteger> ClassicalAtomicPatternServerKey<KeyswitchScalar> {
    pub fn from_raw_parts(
        key_switching_key: LweKeyswitchKeyOwned<KeyswitchScalar>,
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

impl AtomicPatternOperations for ClassicalAtomicPatternServerKey<u64> {
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
            ShortintBootstrappingKey::Classic(_) => MsDecompressionType::ClassicPbs,
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
}

impl AtomicPatternMutOperations for ClassicalAtomicPatternServerKey<u64> {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution)
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

    fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Classical(ap) => ap.ciphertext_modulus(),
            Self::KeySwitch32(_) => todo!(),
        }
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        match self {
            Self::Classical(ap) => ap.ciphertext_decompression_method(),
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

    fn atomic_pattern(&self) -> AtomicPattern {
        match self {
            Self::Classical(ap) => ap.atomic_pattern(),
            Self::KeySwitch32(_) => todo!(),
        }
    }

    fn deterministic_execution(&self) -> bool {
        match self {
            Self::Classical(ap) => ap.deterministic_execution(),
            Self::KeySwitch32(_) => todo!(),
        }
    }
}

impl AtomicPatternMutOperations for ServerKeyAtomicPattern {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            Self::Classical(ap) => ap.set_deterministic_execution(new_deterministic_execution),
            Self::KeySwitch32(_) => todo!(),
        }
    }
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize, NotVersioned)]
pub enum AtomicPatternParameters {
    Classical(PBSParameters),
}

impl From<ClassicPBSParameters> for AtomicPatternParameters {
    fn from(value: ClassicPBSParameters) -> Self {
        Self::Classical(PBSParameters::PBS(value))
    }
}

impl From<MultiBitPBSParameters> for AtomicPatternParameters {
    fn from(value: MultiBitPBSParameters) -> Self {
        Self::Classical(PBSParameters::MultiBitPBS(value))
    }
}

// TODO: make this more generic
impl From<AtomicPatternParameters> for PBSParameters {
    fn from(value: AtomicPatternParameters) -> Self {
        match value {
            AtomicPatternParameters::Classical(pbsparameters) => pbsparameters,
        }
    }
}

impl AtomicPatternParameters {
    pub fn message_modulus(&self) -> MessageModulus {
        match self {
            Self::Classical(pbsparameters) => pbsparameters.message_modulus(),
        }
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        match self {
            Self::Classical(pbsparameters) => pbsparameters.carry_modulus(),
        }
    }

    pub fn max_noise_level(&self) -> MaxNoiseLevel {
        match self {
            Self::Classical(pbsparameters) => pbsparameters.max_noise_level(),
        }
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Classical(pbsparameters) => pbsparameters.ciphertext_modulus(),
        }
    }
}

impl ParameterSetConformant for ServerKeyAtomicPattern {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::Classical(ap), AtomicPatternParameters::Classical(params)) => {
                ap.is_conformant(params)
            }
            _ => false,
        }
    }
}

impl From<ClassicalAtomicPatternServerKey<u64>> for ServerKeyAtomicPattern {
    fn from(value: ClassicalAtomicPatternServerKey<u64>) -> Self {
        Self::Classical(value)
    }
}

impl From<ClassicalAtomicPatternServerKey<u32>> for ServerKeyAtomicPattern {
    fn from(value: ClassicalAtomicPatternServerKey<u32>) -> Self {
        Self::KeySwitch32(value)
    }
}
