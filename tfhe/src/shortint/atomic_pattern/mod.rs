//! An atomic pattern is a sequence of homomorphic operations that can be executed
//! indefinitely.
//!
//! For example, in TFHE the standard atomic pattern is the chain of n linear operations, a
//! Keyswitch and a PBS.

pub mod classical;

use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{LweCiphertextOwned, LweDimension, MsDecompressionType};

use super::backward_compatibility::atomic_pattern::*;
use super::server_key::{
    apply_blind_rotate, apply_programmable_bootstrap, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned,
};
use super::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, MaxNoiseLevel,
    MessageModulus, MultiBitPBSParameters, PBSOrder, PBSParameters,
};

pub use classical::*;

/// A choice of atomic pattern
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Versionize)]
#[versionize(AtomicPatternKindVersions)]
pub enum AtomicPatternKind {
    /// The classical TFHE Atomic Pattern, as described here: <https://eprint.iacr.org/2021/091.pdf>
    ///
    /// `n linear operations + Keyswitch + Bootstrap`, or `n linear operations +  Bootstrap +
    /// Keyswitch` based on the [`PBSOrder`].
    Classical(PBSOrder),
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
    /// The output in in the form 0000rrr000noise (rbc=3, fbc=7)
    /// The encryted value is oblivious to the server
    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> LweCiphertextOwned<u64>;

    /// Returns true if the Atomic Pattern will execute deterministically
    fn deterministic_execution(&self) -> bool;
}

pub trait AtomicPatternMut: AtomicPattern {
    /// Configures the atomic pattern for deterministic execution
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool);
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
    ) -> LweCiphertextOwned<u64> {
        (*self).generate_oblivious_pseudo_random(seed, random_bits_count, full_bits_count)
    }

    fn deterministic_execution(&self) -> bool {
        (*self).deterministic_execution()
    }
}

/// The server key materials for all the supported Atomic Patterns
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(AtomicPatternServerKeyVersions)]
pub enum AtomicPatternServerKey {
    Classical(ClassicalAtomicPatternServerKey),
}

impl AtomicPattern for AtomicPatternServerKey {
    fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classical(ap) => ap.ciphertext_lwe_dimension(),
        }
    }

    fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Classical(ap) => ap.ciphertext_modulus(),
        }
    }

    fn ciphertext_decompression_method(&self) -> MsDecompressionType {
        match self {
            Self::Classical(ap) => ap.ciphertext_decompression_method(),
        }
    }

    fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        match self {
            Self::Classical(ap) => ap.apply_lookup_table_assign(ct, acc),
        }
    }

    fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        match self {
            Self::Classical(ap) => ap.apply_many_lookup_table(ct, lut),
        }
    }

    fn lookup_table_size(&self) -> LookupTableSize {
        match self {
            Self::Classical(ap) => ap.lookup_table_size(),
        }
    }

    fn kind(&self) -> AtomicPatternKind {
        match self {
            Self::Classical(ap) => ap.kind(),
        }
    }

    fn deterministic_execution(&self) -> bool {
        match self {
            Self::Classical(ap) => ap.deterministic_execution(),
        }
    }

    fn generate_oblivious_pseudo_random(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
    ) -> LweCiphertextOwned<u64> {
        match self {
            Self::Classical(ap) => {
                ap.generate_oblivious_pseudo_random(seed, random_bits_count, full_bits_count)
            }
        }
    }
}

impl AtomicPatternMut for AtomicPatternServerKey {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            Self::Classical(ap) => ap.set_deterministic_execution(new_deterministic_execution),
        }
    }
}

/// Set of parameters that can be used to create a key for any Atomic Pattern
#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(AtomicPatternParametersVersions)]
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
            AtomicPatternParameters::Classical(parameters) => parameters,
        }
    }
}

impl AtomicPatternParameters {
    pub fn message_modulus(&self) -> MessageModulus {
        match self {
            Self::Classical(parameters) => parameters.message_modulus(),
        }
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        match self {
            Self::Classical(parameters) => parameters.carry_modulus(),
        }
    }

    pub fn max_noise_level(&self) -> MaxNoiseLevel {
        match self {
            Self::Classical(parameters) => parameters.max_noise_level(),
        }
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus {
        match self {
            Self::Classical(parameters) => parameters.ciphertext_modulus(),
        }
    }
}

impl ParameterSetConformant for AtomicPatternServerKey {
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

impl From<ClassicalAtomicPatternServerKey> for AtomicPatternServerKey {
    fn from(value: ClassicalAtomicPatternServerKey) -> Self {
        Self::Classical(value)
    }
}
