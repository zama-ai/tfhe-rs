//! An atomic pattern is a sequence of homomorphic operations that can be executed
//! indefinitely.
//!
//! For example, in TFHE the standard atomic pattern is the chain of n linear operations, a
//! Keyswitch and a PBS.

pub mod classical;

use serde::{Deserialize, Serialize};
use tfhe_csprng::seeders::Seed;
use tfhe_versionable::NotVersioned;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::{
    GlweDimension, LweCiphertextOwned, LweDimension, MsDecompressionType, PolynomialSize,
};

use super::ciphertext::CompressedModulusSwitchedCiphertext;
use super::server_key::{
    apply_blind_rotate, apply_programmable_bootstrap, LookupTableOwned, LookupTableSize,
    ManyLookupTableOwned,
};
use super::{
    CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, MaxNoiseLevel,
    MessageModulus, MultiBitPBSParameters, PBSOrder, PBSParameters, ShortintParameterSet,
};

pub use classical::*;

/// A choice of atomic pattern
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, NotVersioned)]
pub enum AtomicPattern {
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
pub trait AtomicPatternOperations {
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

    fn atomic_pattern(&self) -> AtomicPattern;

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

    /// Compresses a ciphertext to have a smaller serialization size
    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext;

    /// Decompresses a compressed ciphertext
    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext;

    /// Convert the ciphertext to a state where it is ready for noise squashing
    ///
    /// Basically, this means getting it ready for the 128b PBS, for example by doing a keyswitch
    fn prepare_for_noise_squashing(&self, ct: &Ciphertext) -> LweCiphertextOwned<u64>;
}

pub trait AtomicPatternMutOperations: AtomicPatternOperations {
    /// Configures the atomic pattern for deterministic execution
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool);
}

// This blancket impl is used to allow "views" of server keys, without having to re-implement the
// trait
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

    fn prepare_for_noise_squashing(&self, ct: &Ciphertext) -> LweCiphertextOwned<u64> {
        (*self).prepare_for_noise_squashing(ct)
    }
}

/// The server key materials for all the supported Atomic Patterns
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, NotVersioned)] // TODO: Versionize
pub enum ServerKeyAtomicPattern {
    Classical(ClassicalAtomicPatternServerKey),
}

impl AtomicPatternOperations for ServerKeyAtomicPattern {
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

    fn atomic_pattern(&self) -> AtomicPattern {
        match self {
            Self::Classical(ap) => ap.atomic_pattern(),
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

    fn switch_modulus_and_compress(&self, ct: &Ciphertext) -> CompressedModulusSwitchedCiphertext {
        match self {
            Self::Classical(ap) => ap.switch_modulus_and_compress(ct),
        }
    }

    fn decompress_and_apply_lookup_table(
        &self,
        compressed_ct: &CompressedModulusSwitchedCiphertext,
        lut: &LookupTableOwned,
    ) -> Ciphertext {
        match self {
            Self::Classical(ap) => ap.decompress_and_apply_lookup_table(compressed_ct, lut),
        }
    }

    fn prepare_for_noise_squashing(&self, ct: &Ciphertext) -> LweCiphertextOwned<u64> {
        match self {
            Self::Classical(ap) => ap.prepare_for_noise_squashing(ct),
        }
    }
}

impl AtomicPatternMutOperations for ServerKeyAtomicPattern {
    fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            Self::Classical(ap) => ap.set_deterministic_execution(new_deterministic_execution),
        }
    }
}

/// Set of parameters that can be used to create a key for any Atomic Pattern
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

impl From<AtomicPatternParameters> for ShortintParameterSet {
    fn from(value: AtomicPatternParameters) -> Self {
        match value {
            AtomicPatternParameters::Classical(parameters) => parameters.into(),
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

    pub fn lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classical(parameters) => parameters.lwe_dimension(),
        }
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        match self {
            Self::Classical(parameters) => parameters.glwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classical(parameters) => parameters.polynomial_size(),
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

impl From<ClassicalAtomicPatternServerKey> for ServerKeyAtomicPattern {
    fn from(value: ClassicalAtomicPatternServerKey) -> Self {
        Self::Classical(value)
    }
}
