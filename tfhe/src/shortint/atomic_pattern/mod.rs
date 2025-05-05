//! An atomic pattern is a sequence of homomorphic operations that can be executed
//! indefinitely.
//!
//! For example, in TFHE the standard atomic pattern is the chain of n linear operations, a
//! Keyswitch and a PBS.

pub mod standard;

use std::any::Any;

use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    GlweDimension, LweCiphertextOwned, LweDimension, MsDecompressionType, PolynomialSize,
};

use super::backward_compatibility::atomic_pattern::*;
use super::ciphertext::{CompressedModulusSwitchedCiphertext, Degree};
use super::engine::ShortintEngine;
use super::server_key::{
    apply_blind_rotate, apply_programmable_bootstrap, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned,
};
use super::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, ClientKey, MaxNoiseLevel,
    MessageModulus, MultiBitPBSParameters, PBSOrder, PBSParameters, ShortintParameterSet,
};

pub use standard::*;

/// A choice of atomic pattern
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Versionize)]
#[versionize(AtomicPatternKindVersions)]
pub enum AtomicPatternKind {
    /// The Standard TFHE Atomic Pattern, that correspond to what was done before TFHE-rs 1.2.
    ///
    /// This is actually a "meta" atomic pattern, that can be configured in several ways:
    /// - PBS order (KS -> Bootstrap or Bootstrap -> Keyswitch)
    /// - PBS kind (classic or multibit)
    Standard(PBSOrder),
}

/// The set of operations needed to implement an Atomic Pattern.
///
/// Here the definition of Atomic Pattern is a bit more TFHE-specific and includes the evaluation of
/// a lookup table. It does not, however, include the sequence of linear operations.
///
/// The atomic pattern can be seen as a black box that will apply a lookup table and refresh the
/// ciphertext noise to a nominal level. Between applications of the AP, it is possible to do a
/// certain number of linear operations.
pub trait AtomicPattern {
    /// The LWE dimension of the ciphertext used as input and output of the AP
    fn ciphertext_lwe_dimension(&self) -> LweDimension;

    /// The modulus of the ciphertext used as input and output of the AP
    fn ciphertext_modulus(&self) -> CiphertextModulus;

    /// Decompression method used to extract cipherexts compressed with the modulus switch
    /// compression
    fn ciphertext_decompression_method(&self) -> MsDecompressionType;

    /// Performs a full application of the atomic pattern, and modify the input [`Ciphertext`]
    /// in-place.
    ///
    /// After a call to this function, the ciphertext should encrypt a value that is the output of
    /// the lookup table, and the noise should be set to a nominal level.
    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned);

    /// Applies many lookup tables on a single ciphertext
    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext>;

    /// The size of the lookup tables applied by this Atomic Pattern
    fn lookup_table_size(&self) -> LookupTableSize;

    fn kind(&self) -> AtomicPatternKind;

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    ///
    /// `full_bits_count` is the size of the lwe message, ie the shortint message + carry + padding
    /// bit.
    /// The output in in the form 0000rrr000noise (random_bits_count=3, full_bits_count=7)
    /// The encryted value is oblivious to the server
    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> (LweCiphertextOwned<u64>, Degree);

    /// Returns true if the Atomic Pattern will execute deterministically
    fn deterministic_execution(&self) -> bool;

    /// Compresses a ciphertext to have a smaller serialization size
    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext;

    /// Decompresses a compressed ciphertext
    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext;
}

pub trait AtomicPatternMut: AtomicPattern {
    /// Configures the atomic pattern for deterministic execution
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool);
}

// Prevent user implementation of this trait
mod private {
    use super::*;
    /// This trait allow the use of [`AtomicPatternOperations`] in a dynamic context.
    ///
    /// It should be automatically derived for types that implement "PartialEq + Clone +
    /// AtomicPatternMut"
    pub trait DynamicAtomicPattern:
        AtomicPatternMut
        + Send
        + Sync
        + std::panic::UnwindSafe
        + std::panic::RefUnwindSafe
        + std::fmt::Debug
    {
        fn as_any(&self) -> &dyn Any;
        fn dyn_eq(&self, other: &dyn DynamicAtomicPattern) -> bool;
        fn dyn_clone(&self) -> Box<dyn DynamicAtomicPattern>;
    }

    impl<AP> DynamicAtomicPattern for AP
    where
        AP: 'static
            + PartialEq
            + Clone
            + AtomicPatternMut
            + Send
            + Sync
            + std::panic::UnwindSafe
            + std::panic::RefUnwindSafe
            + std::fmt::Debug,
    {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn dyn_eq(&self, other: &dyn DynamicAtomicPattern) -> bool {
            // Do a type-safe casting. If the types are different,
            // return false, otherwise test the values for equality.
            other.as_any().downcast_ref::<AP>() == Some(self)
        }

        fn dyn_clone(&self) -> Box<dyn DynamicAtomicPattern> {
            Box::new(self.clone())
        }
    }

    impl Clone for Box<dyn DynamicAtomicPattern> {
        fn clone(&self) -> Self {
            self.dyn_clone()
        }
    }

    impl PartialEq for Box<dyn DynamicAtomicPattern> {
        fn eq(&self, other: &Self) -> bool {
            self.dyn_eq(other.as_ref())
        }
    }
}

// This blancket impl is used to allow "views" of server keys, without having to re-implement the
// trait
impl<T: AtomicPattern> AtomicPattern for &T {
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

    fn kind(&self) -> AtomicPatternKind {
        (*self).kind()
    }

    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> (LweCiphertextOwned<u64>, Degree) {
        (*self).generate_oblivious_pseudo_random(seed, random_bits_count, full_bits_count)
    }

    fn deterministic_execution(&self) -> bool {
        (*self).deterministic_execution()
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        (*self).switch_modulus_and_compress(ct)
    }

    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext {
        (*self).decompress_and_apply_lookup_table(compressed_ct, lut)
    }
}

/// The server key materials for all the supported Atomic Patterns
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(AtomicPatternServerKeyVersions)]
#[allow(clippy::large_enum_variant)] // The most common variant should be `Standard` so we optimize for it
pub enum AtomicPatternServerKey {
    Standard(StandardAtomicPatternServerKey),
    #[serde(skip)]
    Dynamic(Box<dyn private::DynamicAtomicPattern>),
}

impl AtomicPatternServerKey {
    pub fn new(cks: &ClientKey, engine: &mut ShortintEngine) -> Self {
        let params = &cks.parameters;

        match params.ap_parameters().unwrap() {
            AtomicPatternParameters::Standard(_) => {
                Self::Standard(StandardAtomicPatternServerKey::new(cks, engine))
            }
        }
    }
}

impl AtomicPattern for AtomicPatternServerKey {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Standard(ap) => ap.ciphertext_lwe_dimension(),
            Self::Dynamic(ap) => ap.ciphertext_lwe_dimension(),
        }
    }

    fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Standard(ap) => ap.ciphertext_modulus(),
            Self::Dynamic(ap) => ap.ciphertext_modulus(),
        }
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        match self {
            Self::Standard(ap) => ap.ciphertext_decompression_method(),
            Self::Dynamic(ap) => ap.ciphertext_decompression_method(),
        }
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        match self {
            Self::Standard(ap) => ap.apply_lookup_table_assign(ct, acc),
            Self::Dynamic(ap) => ap.apply_lookup_table_assign(ct, acc),
        }
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        match self {
            Self::Standard(ap) => ap.apply_many_lookup_table(ct, lut),
            Self::Dynamic(ap) => ap.apply_many_lookup_table(ct, lut),
        }
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        match self {
            Self::Standard(ap) => ap.lookup_table_size(),
            Self::Dynamic(ap) => ap.lookup_table_size(),
        }
    }

    fn kind(&self) -> AtomicPatternKind {
        match self {
            Self::Standard(ap) => ap.kind(),
            Self::Dynamic(ap) => ap.kind(),
        }
    }

    fn deterministic_execution(&self) -> bool {
        match self {
            Self::Standard(ap) => ap.deterministic_execution(),
            Self::Dynamic(ap) => ap.deterministic_execution(),
        }
    }

    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> (LweCiphertextOwned<u64>, Degree) {
        match self {
            Self::Standard(ap) => {
                ap.generate_oblivious_pseudo_random(seed, random_bits_count, full_bits_count)
            }
            Self::Dynamic(ap) => {
                ap.generate_oblivious_pseudo_random(seed, random_bits_count, full_bits_count)
            }
        }
    }

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        match self {
            Self::Standard(ap) => ap.switch_modulus_and_compress(ct),
            Self::Dynamic(ap) => ap.switch_modulus_and_compress(ct),
        }
    }

    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext {
        match self {
            Self::Standard(ap) => ap.decompress_and_apply_lookup_table(compressed_ct, lut),
            Self::Dynamic(ap) => ap.decompress_and_apply_lookup_table(compressed_ct, lut),
        }
    }
}

impl AtomicPatternMut for AtomicPatternServerKey {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            Self::Standard(ap) => ap.set_deterministic_execution(new_deterministic_execution),
            Self::Dynamic(ap) => ap.set_deterministic_execution(new_deterministic_execution),
        }
    }
}

/// Set of parameters that can be used to create a key for any Atomic Pattern
#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(AtomicPatternParametersVersions)]
pub enum AtomicPatternParameters {
    Standard(PBSParameters),
}

impl From<PBSParameters> for AtomicPatternParameters {
    fn from(value: PBSParameters) -> Self {
        Self::Standard(value)
    }
}

impl From<ClassicPBSParameters> for AtomicPatternParameters {
    fn from(value: ClassicPBSParameters) -> Self {
        Self::Standard(PBSParameters::PBS(value))
    }
}

impl From<MultiBitPBSParameters> for AtomicPatternParameters {
    fn from(value: MultiBitPBSParameters) -> Self {
        Self::Standard(PBSParameters::MultiBitPBS(value))
    }
}

impl From<AtomicPatternParameters> for ShortintParameterSet {
    fn from(value: AtomicPatternParameters) -> Self {
        match value {
            AtomicPatternParameters::Standard(parameters) => parameters.into(),
        }
    }
}

impl AtomicPatternParameters {
    pub fn message_modulus(&self) -> MessageModulus {
        match self {
            Self::Standard(parameters) => parameters.message_modulus(),
        }
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        match self {
            Self::Standard(parameters) => parameters.carry_modulus(),
        }
    }

    pub fn max_noise_level(&self) -> MaxNoiseLevel {
        match self {
            Self::Standard(parameters) => parameters.max_noise_level(),
        }
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Standard(parameters) => parameters.ciphertext_modulus(),
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Standard(parameters) => parameters.lwe_dimension(),
        }
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::Standard(parameters) => parameters.glwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Standard(parameters) => parameters.polynomial_size(),
        }
    }
}

impl ParameterSetConformant for AtomicPatternServerKey {
    type ParameterSet = AtomicPatternParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set) {
            (Self::Standard(ap), AtomicPatternParameters::Standard(params)) => {
                ap.is_conformant(params)
            }
            _ => false,
        }
    }
}

impl From<StandardAtomicPatternServerKey> for AtomicPatternServerKey {
    fn from(value: StandardAtomicPatternServerKey) -> Self {
        Self::Standard(value)
    }
}
