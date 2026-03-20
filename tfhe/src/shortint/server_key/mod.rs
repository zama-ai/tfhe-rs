//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
mod add;
mod bitwise_op;
mod bivariate_pbs;
mod comp_op;
mod div_mod;
mod modulus_switch_noise_reduction;
mod modulus_switched_compression;
mod mul;
mod neg;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_div_mod;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

pub mod compressed;
pub mod expanded;

pub use expanded::{ShortintExpandedBootstrappingKey, ShortintExpandedServerKey};

pub use bivariate_pbs::{
    BivariateLookupTableMutView, BivariateLookupTableOwned, BivariateLookupTableView,
};
pub use compressed::{CompressedServerKey, ShortintCompressedBootstrappingKey};
pub use modulus_switch_noise_reduction::*;
pub(crate) use modulus_switched_compression::{
    decompress_and_apply_lookup_table, switch_modulus_and_compress,
};
pub(crate) use scalar_mul::unchecked_scalar_mul_assign;

#[cfg(test)]
pub(crate) mod tests;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, GlweSize, LweBskGroupingFactor,
    LweDimension, LweSize, MonomialDegree, PolynomialSize, ThreadCount,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use crate::core_crypto::prelude::{ComputationBuffers, Fft, Fft128};
use crate::shortint::ciphertext::{Ciphertext, Degree, MaxDegree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::{
    fill_accumulator_no_encoding, fill_accumulator_with_encoding, fill_many_lut_accumulator,
    ShortintEngine,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CiphertextModulus, MessageModulus, ModulusSwitchType,
};
use crate::shortint::{PaddingBit, ShortintEncoding};
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

#[cfg(feature = "pbs-stats")]
pub mod pbs_stats {
    use std::sync::atomic::AtomicU64;
    pub use std::sync::atomic::Ordering;
    pub static PBS_COUNT: AtomicU64 = AtomicU64::new(0);

    pub fn get_pbs_count() -> u64 {
        PBS_COUNT.load(Ordering::Relaxed)
    }

    pub fn reset_pbs_count() {
        PBS_COUNT.store(0, Ordering::Relaxed);
    }
}
#[cfg(feature = "pbs-stats")]
pub use pbs_stats::*;

use super::atomic_pattern::{
    AtomicPattern, AtomicPatternMut, AtomicPatternParameters, AtomicPatternServerKey,
    KS32AtomicPatternServerKey, StandardAtomicPatternServerKey,
};
use super::backward_compatibility::server_key::{
    GenericServerKeyVersions, SerializableShortintBootstrappingKeyVersions,
};
use super::ciphertext::{
    unchecked_create_trivial_with_lwe_size, CompressedModulusSwitchedCiphertextConformanceParams,
};
use super::noise_squashing::Shortint128BootstrappingKey;
use super::parameters::KeySwitch32PBSParameters;
use super::PBSParameters;

/// Error returned when the carry buffer is full.
#[derive(Debug)]
pub enum CheckError {
    CarryFull {
        degree: Degree,
        max_degree: MaxDegree,
    },
    NoiseTooBig {
        noise_level: NoiseLevel,
        max_noise_level: MaxNoiseLevel,
    },
    UnscaledScaledOverlap {
        unscaled_degree: Degree,
        scale: u8,
    },
}

impl Display for CheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CarryFull { degree, max_degree } => {
                write!(
                    f,
                    "The degree (={}) should not exceed {}",
                    degree.get(),
                    max_degree.get(),
                )
            }
            Self::NoiseTooBig {
                noise_level,
                max_noise_level,
            } => {
                write!(
                    f,
                    "The noise (={}) should not exceed {}",
                    noise_level.get(),
                    max_noise_level.get(),
                )
            }
            Self::UnscaledScaledOverlap {
                unscaled_degree,
                scale,
            } => {
                write!(
                    f,
                    "The scale (={}) should be bigger than the unscaled degree (={})",
                    scale,
                    unscaled_degree.get(),
                )
            }
        }
    }
}

impl std::error::Error for CheckError {}

#[derive(Clone, Debug, PartialEq, Versionize)]
#[versionize(convert = "SerializableShortintBootstrappingKey<InputScalar, ABox<[tfhe_fft::c64]>>")]
pub enum ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    Classic {
        bsk: FourierLweBootstrapKeyOwned,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<InputScalar>,
    },
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned, InputScalar: for<'a> Deserialize<'a>"))]
#[versionize(SerializableShortintBootstrappingKeyVersions)]
pub enum SerializableShortintBootstrappingKey<InputScalar, C: Container<Element = tfhe_fft::c64>>
where
    InputScalar: UnsignedInteger,
{
    Classic {
        bsk: FourierLweBootstrapKey<C>,
        modulus_switch_noise_reduction_key: ModulusSwitchConfiguration<InputScalar>,
    },
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl<InputScalar, C: Container<Element = tfhe_fft::c64>>
    SerializableShortintBootstrappingKey<InputScalar, C>
where
    InputScalar: UnsignedInteger,
{
    /// Returns `true` if the serializable shortint bootstrapping key is [`Classic`].
    ///
    /// [`Classic`]: SerializableShortintBootstrappingKey::Classic
    #[must_use]
    pub fn is_classic(&self) -> bool {
        matches!(self, Self::Classic { .. })
    }
}

impl<'a, InputScalar> From<&'a ShortintBootstrappingKey<InputScalar>>
    for SerializableShortintBootstrappingKey<InputScalar, &'a [tfhe_fft::c64]>
where
    InputScalar: UnsignedInteger,
{
    fn from(value: &'a ShortintBootstrappingKey<InputScalar>) -> Self {
        match value {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => Self::Classic {
                bsk: bsk.as_view(),
                modulus_switch_noise_reduction_key: modulus_switch_noise_reduction_key.clone(),
            },
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: bsk,
                deterministic_execution,
                ..
            } => Self::MultiBit {
                fourier_bsk: bsk.as_view(),
                deterministic_execution: *deterministic_execution,
            },
        }
    }
}

impl<InputScalar> From<ShortintBootstrappingKey<InputScalar>>
    for SerializableShortintBootstrappingKey<InputScalar, ABox<[tfhe_fft::c64]>>
where
    InputScalar: UnsignedInteger,
{
    fn from(value: ShortintBootstrappingKey<InputScalar>) -> Self {
        match value {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            },
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                deterministic_execution,
                ..
            } => Self::MultiBit {
                fourier_bsk,
                deterministic_execution,
            },
        }
    }
}

impl<InputScalar> Serialize for ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableShortintBootstrappingKey::from(self).serialize(serializer)
    }
}

impl<InputScalar> From<SerializableShortintBootstrappingKey<InputScalar, ABox<[tfhe_fft::c64]>>>
    for ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    fn from(
        value: SerializableShortintBootstrappingKey<InputScalar, ABox<[tfhe_fft::c64]>>,
    ) -> Self {
        match value {
            SerializableShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => Self::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            },
            SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                deterministic_execution,
            } => {
                let thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                    fourier_bsk.input_lwe_dimension(),
                    fourier_bsk.glwe_size().to_glwe_dimension(),
                    fourier_bsk.polynomial_size(),
                    fourier_bsk.decomposition_base_log(),
                    fourier_bsk.decomposition_level_count(),
                    fourier_bsk.grouping_factor(),
                );
                Self::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

impl<'de, InputScalar> Deserialize<'de> for ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger + for<'a> Deserialize<'a>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deser_sk = SerializableShortintBootstrappingKey::deserialize(deserializer)?;
        Ok(Self::from(deser_sk))
    }
}

impl<InputScalar> ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    pub fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.input_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.input_lwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic { bsk, .. } => bsk.polynomial_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic { bsk, .. } => bsk.glwe_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.glwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic { bsk, .. } => bsk.decomposition_base_log(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_base_log(),
        }
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic { bsk, .. } => bsk.decomposition_level_count(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_level_count(),
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic { bsk, .. } => bsk.output_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.output_lwe_dimension(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match self {
            Self::Classic { bsk, .. } => bsk.as_view().data().len(),
            Self::MultiBit {
                fourier_bsk: bsk, ..
            } => bsk.as_view().data().len(),
        }
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match self {
            Self::Classic { bsk, .. } => std::mem::size_of_val(bsk.as_view().data()),
            Self::MultiBit {
                fourier_bsk: bsk, ..
            } => std::mem::size_of_val(bsk.as_view().data()),
        }
    }

    /// Indicate whether the PBS algorithm is deterministic, i.e. will produce the same bit-exact
    /// output when run twice on the same bit-exact input.
    ///
    /// Note: the classic PBS algorithm is always deterministic.
    pub fn deterministic_pbs_execution(&self) -> bool {
        match self {
            Self::Classic { .. } => true,
            Self::MultiBit {
                deterministic_execution,
                ..
            } => *deterministic_execution,
        }
    }

    /// Set the choice of PBS algorithm to have the `new_deterministic_execution` behavior.
    ///
    /// Note: the classic PBS algorithm is always deterministic and calling this function on a
    /// [`ServerKey`] made from [`super::ClassicPBSParameters`] is a no-op.
    pub fn set_deterministic_pbs_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            // Classic PBS is already deterministic no matter what
            Self::Classic { .. } => (),
            Self::MultiBit {
                deterministic_execution,
                ..
            } => *deterministic_execution = new_deterministic_execution,
        }
    }

    /// Recomputes the number of threads required for the multi bit PBS.
    ///
    /// It may be useful to call this function when the CPU usage is low and predictable to have a
    /// better value for the number of threads to use for the multi bit PBS.
    ///
    /// Has not effects for other keys.
    pub fn recompute_thread_count(&mut self) {
        match self {
            Self::Classic { .. } => (),
            Self::MultiBit {
                fourier_bsk,
                thread_count,
                ..
            } => {
                *thread_count = ShortintEngine::get_thread_count_for_multi_bit_pbs(
                    fourier_bsk.input_lwe_dimension(),
                    fourier_bsk.glwe_size().to_glwe_dimension(),
                    fourier_bsk.polynomial_size(),
                    fourier_bsk.decomposition_base_log(),
                    fourier_bsk.decomposition_level_count(),
                    fourier_bsk.grouping_factor(),
                )
            }
        }
    }

    pub fn modulus_switch_configuration(&self) -> Option<&ModulusSwitchConfiguration<InputScalar>> {
        match self {
            Self::Classic {
                bsk: _,
                modulus_switch_noise_reduction_key,
            } => Some(modulus_switch_noise_reduction_key),
            Self::MultiBit { .. } => None,
        }
    }
}

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(GenericServerKeyVersions)]
pub struct GenericServerKey<AP> {
    pub atomic_pattern: AP,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    // Modulus use for computations on the ciphertext
    pub ciphertext_modulus: CiphertextModulus,
}

impl<AP: Clone> GenericServerKey<&AP> {
    pub fn owned(&self) -> GenericServerKey<AP> {
        GenericServerKey {
            atomic_pattern: self.atomic_pattern.clone(),
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            max_degree: self.max_degree,
            max_noise_level: self.max_noise_level,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

pub type ServerKey = GenericServerKey<AtomicPatternServerKey>;
pub type StandardServerKey = GenericServerKey<StandardAtomicPatternServerKey>;
pub type ServerKeyView<'key> = GenericServerKey<&'key AtomicPatternServerKey>;
pub type StandardServerKeyView<'key> = GenericServerKey<&'key StandardAtomicPatternServerKey>;
pub type KS32ServerKeyView<'key> = GenericServerKey<&'key KS32AtomicPatternServerKey>;

// Manual implementations of Copy because the derive will require AP to be Copy,
// which is actually overrestrictive: https://github.com/rust-lang/rust/issues/26925
impl Copy for StandardServerKeyView<'_> {}
impl Copy for KS32ServerKeyView<'_> {}
impl Copy for ServerKeyView<'_> {}

impl From<StandardServerKey> for ServerKey {
    fn from(value: StandardServerKey) -> Self {
        let atomic_pattern = AtomicPatternServerKey::Standard(value.atomic_pattern);

        Self {
            atomic_pattern,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            max_degree: value.max_degree,
            max_noise_level: value.max_noise_level,
            ciphertext_modulus: value.ciphertext_modulus,
        }
    }
}

#[derive(Debug)]
pub struct UnsupportedOperation;

impl Display for UnsupportedOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation not supported by the current configuration")
    }
}

impl std::error::Error for UnsupportedOperation {}

impl TryFrom<ServerKey> for StandardServerKey {
    type Error = UnsupportedOperation;

    fn try_from(value: ServerKey) -> Result<Self, Self::Error> {
        let AtomicPatternServerKey::Standard(atomic_pattern) = value.atomic_pattern else {
            return Err(UnsupportedOperation);
        };

        Ok(Self {
            atomic_pattern,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            max_degree: value.max_degree,
            max_noise_level: value.max_noise_level,
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}

impl<'key> TryFrom<ServerKeyView<'key>> for StandardServerKeyView<'key> {
    type Error = UnsupportedOperation;

    fn try_from(value: ServerKeyView<'key>) -> Result<Self, Self::Error> {
        let AtomicPatternServerKey::Standard(atomic_pattern) = value.atomic_pattern else {
            return Err(UnsupportedOperation);
        };

        Ok(Self {
            atomic_pattern,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            max_degree: value.max_degree,
            max_noise_level: value.max_noise_level,
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}

impl<'key> TryFrom<ServerKeyView<'key>> for KS32ServerKeyView<'key> {
    type Error = UnsupportedOperation;

    fn try_from(value: ServerKeyView<'key>) -> Result<Self, Self::Error> {
        let AtomicPatternServerKey::KeySwitch32(atomic_pattern) = value.atomic_pattern else {
            return Err(UnsupportedOperation);
        };

        Ok(Self {
            atomic_pattern,
            message_modulus: value.message_modulus,
            carry_modulus: value.carry_modulus,
            max_degree: value.max_degree,
            max_noise_level: value.max_noise_level,
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}

/// The number of elements in a [`LookupTable`] represented by a Glwe ciphertext
#[derive(Copy, Clone, Debug)]
pub struct LookupTableSize {
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
}

impl LookupTableSize {
    pub fn new(glwe_size: GlweSize, polynomial_size: PolynomialSize) -> Self {
        Self {
            glwe_size,
            polynomial_size,
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct LookupTable<C: Container<Element = u64>> {
    pub acc: GlweCiphertext<C>,
    pub degree: Degree,
}

pub type LookupTableOwned = LookupTable<Vec<u64>>;
pub type LookupTableMutView<'a> = LookupTable<&'a mut [u64]>;
pub type LookupTableView<'a> = LookupTable<&'a [u64]>;

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ManyLookupTable<C: Container<Element = u64>> {
    pub acc: GlweCiphertext<C>,
    pub input_max_degree: MaxDegree,
    pub sample_extraction_stride: usize,
    pub per_function_output_degree: Vec<Degree>,
}

pub type ManyLookupTableOwned = ManyLookupTable<Vec<u64>>;
pub type ManyLookupTableMutView<'a> = ManyLookupTable<&'a mut [u64]>;
pub type ManyLookupTableView<'a> = ManyLookupTable<&'a [u64]>;

impl<C: Container<Element = u64>> ManyLookupTable<C> {
    pub fn function_count(&self) -> usize {
        self.per_function_output_degree.len()
    }
}

impl ServerKey {
    /// Generate a server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, ServerKey};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new(&cks);
    /// ```
    pub fn new(cks: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_server_key(cks))
    }

    /// Generate a server key with a chosen maximum degree
    pub fn new_with_max_degree(cks: &ClientKey, max_degree: MaxDegree) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_server_key_with_max_degree(cks, max_degree)
        })
    }
}

impl<AP: AtomicPattern> GenericServerKey<AP> {
    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        self.atomic_pattern.ciphertext_lwe_dimension()
    }

    pub fn as_view(&self) -> GenericServerKey<&AP> {
        GenericServerKey {
            atomic_pattern: &self.atomic_pattern,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            max_degree: self.max_degree,
            max_noise_level: self.max_noise_level,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    /// Deconstruct a [`ServerKey`] into its constituents.
    pub fn into_raw_parts(self) -> (AP, MessageModulus, CarryModulus, MaxDegree, MaxNoiseLevel) {
        let Self {
            atomic_pattern,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus: _,
        } = self;

        (
            atomic_pattern,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
        )
    }

    /// Construct a [`ServerKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    pub fn from_raw_parts(
        atomic_pattern_key: AP,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_degree: MaxDegree,
        max_noise_level: MaxNoiseLevel,
    ) -> Self {
        let max_max_degree = MaxDegree::from_msg_carry_modulus(message_modulus, carry_modulus);

        assert!(
            max_degree.get() <= max_max_degree.get(),
            "Maximum valid MaxDegree is {max_max_degree:?}, got ({max_degree:?})"
        );

        let ciphertext_modulus = atomic_pattern_key.ciphertext_modulus();

        Self {
            atomic_pattern: atomic_pattern_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
        }
    }

    pub fn conformance_params(&self) -> CiphertextConformanceParams {
        let lwe_dim = self.ciphertext_lwe_dimension();

        let ct_params = LweCiphertextConformanceParams {
            lwe_dim,
            ct_modulus: self.ciphertext_modulus,
        };

        CiphertextConformanceParams {
            ct_params,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: Degree::new(self.message_modulus.0 - 1),
            atomic_pattern: self.atomic_pattern.kind(),
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub fn compressed_modswitched_conformance_params(
        &self,
    ) -> CompressedModulusSwitchedCiphertextConformanceParams {
        let lwe_dim = self.ciphertext_lwe_dimension();

        let ct_params = LweCiphertextConformanceParams {
            lwe_dim,
            ct_modulus: self.ciphertext_modulus,
        };

        let compressed_ct = CompressedModulusSwitchedLweCiphertextConformanceParams {
            ct_params,
            ms_decompression_type: self.atomic_pattern.ciphertext_decompression_method(),
        };

        CompressedModulusSwitchedCiphertextConformanceParams {
            ct_params: compressed_ct,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: Degree::new(self.message_modulus.0 - 1),
            atomic_pattern: self.atomic_pattern.kind(),
        }
    }

    pub(crate) fn encoding(&self, padding_bit: PaddingBit) -> ShortintEncoding<u64> {
        ShortintEncoding {
            ciphertext_modulus: self.ciphertext_modulus,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            padding_bit,
        }
    }

    /// Constructs the lookup table given a function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table for the function f: x -> x*x mod 4
    /// let f = |x: u64| x.pow(2) % 4;
    /// let lut = sks.generate_lookup_table(f);
    /// let ct_res = sks.apply_lookup_table(&ct, &lut);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3**2 mod 4 = 1
    /// assert_eq!(dec, f(msg));
    /// ```
    pub fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let size = self.atomic_pattern.lookup_table_size();
        generate_lookup_table(
            size,
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            f,
        )
    }

    /// Given a function as input, constructs the lookup table working on the message bits
    /// Carry bits are ignored
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table on message for the function f: x -> x*x
    /// let f = |x: u64| x.pow(2);
    ///
    /// let lut = sks.generate_msg_lookup_table(f, ct.message_modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &lut);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg) % 4);
    /// ```
    pub fn generate_msg_lookup_table<F>(&self, f: F, modulus: MessageModulus) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        self.generate_lookup_table(|x| f(x % modulus.0) % modulus.0)
    }

    /// Constructs the lookup table given a set of function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table for the functions
    /// // f1: x -> x*x mod 4
    /// // f2: x -> count_ones(x as binary) mod 4
    /// let f1 = |x: u64| x.pow(2) % 4;
    /// let f2 = |x: u64| x.count_ones() as u64 % 4;
    /// // Easy to use for generation
    /// let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    /// let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    /// // Need to manually help Rust to iterate over them easily
    /// let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    /// for (res, function) in vec_res.iter().zip(functions) {
    ///     let dec = cks.decrypt(res);
    ///     assert_eq!(dec, function(msg));
    /// }
    /// ```
    pub fn generate_many_lookup_table(
        &self,
        functions: &[&dyn Fn(u64) -> u64],
    ) -> ManyLookupTableOwned {
        let lut_size = self.atomic_pattern.lookup_table_size();
        let mut acc = GlweCiphertext::new(
            0,
            lut_size.glwe_size(),
            lut_size.polynomial_size(),
            self.ciphertext_modulus,
        );
        let (input_max_degree, sample_extraction_stride, per_function_output_degree) =
            fill_many_lut_accumulator(
                &mut acc,
                lut_size.polynomial_size(),
                lut_size.glwe_size(),
                self.message_modulus,
                self.carry_modulus,
                functions,
            );

        ManyLookupTableOwned {
            acc,
            input_max_degree,
            sample_extraction_stride,
            per_function_output_degree,
        }
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let ct = cks.encrypt(msg);
    /// let modulus = cks.parameters().message_modulus().0;
    ///
    /// // Generate the lookup table for the function f: x -> x*x*x mod 4
    /// let lut = sks.generate_lookup_table(|x| x * x * x % modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &lut);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // (3*3*3) mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn apply_lookup_table(&self, ct: &Ciphertext, acc: &LookupTableOwned) -> Ciphertext {
        let mut ct_res = ct.clone();

        self.apply_lookup_table_assign(&mut ct_res, acc);

        ct_res
    }

    pub fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        if ct.is_trivial() {
            self.trivial_pbs_assign(ct, acc);
            return;
        }

        self.atomic_pattern.apply_lookup_table_assign(ct, acc);

        ct.degree = acc.degree;
        ct.set_noise_level_to_nominal();
    }

    /// Compute a keyswitch and programmable bootstrap applying several functions on an input
    /// ciphertext, returning each result in a fresh ciphertext.
    ///
    /// This requires the input ciphertext to have a degree inferior to the max degree stored in the
    /// [`ManyLookupTable`] returned by [`Self::generate_many_lookup_table`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table for the functions
    /// // f1: x -> x*x mod 4
    /// // f2: x -> count_ones(x as binary) mod 4
    /// let f1 = |x: u64| x.pow(2) % 4;
    /// let f2 = |x: u64| x.count_ones() as u64 % 4;
    /// // Easy to use for generation
    /// let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    /// let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    /// // Need to manually help Rust to iterate over them easily
    /// let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    /// for (res, function) in vec_res.iter().zip(functions) {
    ///     let dec = cks.decrypt(res);
    ///     assert_eq!(dec, function(msg));
    /// }
    /// ```
    pub fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        if ct.is_trivial() {
            return self.trivial_pbs_many_lut(ct, lut);
        }

        let mut results = self.atomic_pattern.apply_many_lookup_table(ct, lut);

        for ct in results.iter_mut() {
            ct.set_noise_level_to_nominal();
        }

        results
    }

    /// Applies the given function to the message of a ciphertext
    /// The input is reduced to the message space before the function application
    /// Thee output of the function is also rduced to the message space such that the carry bits are
    /// clean on the output
    pub fn evaluate_msg_univariate_function_assign<F>(&self, ct: &mut Ciphertext, f: F)
    where
        F: Fn(u64) -> u64,
    {
        // Generate the lookup table for the function
        let lookup_table = self.generate_msg_lookup_table(f, self.message_modulus);

        self.apply_lookup_table_assign(ct, &lookup_table);
    }

    /// Applies the given function to the message of a ciphertext
    /// The input is reduced to the message space before the function application
    /// Thee output of the function is also rduced to the message space such that the carry bits are
    /// clean on the output
    pub fn evaluate_msg_univariate_function<F>(&self, ct: &Ciphertext, f: F) -> Ciphertext
    where
        F: Fn(u64) -> u64,
    {
        let mut ct_res = ct.clone();

        self.evaluate_msg_univariate_function_assign(&mut ct_res, f);

        ct_res
    }

    /// Replace the input encrypted message by the value of its carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically carry extraction
    /// sks.carry_extract_assign(&mut ct);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(2, res);
    /// ```
    pub fn carry_extract_assign(&self, ct: &mut Ciphertext) {
        let modulus = ct.message_modulus.0;

        let lookup_table = self.generate_lookup_table(|x| x / modulus);

        self.apply_lookup_table_assign(ct, &lookup_table);
    }

    /// Extract a new ciphertext encrypting the input carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically carry extraction
    /// let ct_res = sks.carry_extract(&ct);
    ///
    /// // |     ct_res      |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(2, res);
    /// ```
    pub fn carry_extract(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.carry_extract_assign(&mut result);
        result
    }

    /// Clears the carry buffer of the input ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically the message extraction
    /// sks.message_extract_assign(&mut ct);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct);
    /// assert_eq!(1, res);
    /// ```
    pub fn message_extract_assign(&self, ct: &mut Ciphertext) {
        let acc = self.generate_msg_lookup_table(|x| x, ct.message_modulus);

        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Extract a new ciphertext containing only the message i.e., with a cleared carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically the message extraction
    /// let ct_res = sks.message_extract(&ct);
    ///
    /// // |     ct_res      |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(1, res);
    /// ```
    pub fn message_extract(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.message_extract_assign(&mut result);
        result
    }

    /// Compute a trivial shortint ciphertext with the dimension of the big LWE secret key from a
    /// given value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, Ciphertext};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    ///
    /// // Trivial encryption
    /// let ct1: Ciphertext = sks.create_trivial(msg);
    ///
    /// let ct_res = cks.decrypt(&ct1);
    /// assert_eq!(1, ct_res);
    /// ```
    pub fn create_trivial(&self, value: u64) -> Ciphertext {
        let modular_value = value % self.message_modulus.0;
        self.unchecked_create_trivial(modular_value)
    }

    pub(crate) fn unchecked_create_trivial_with_lwe_size(
        &self,
        value: Cleartext<u64>,
        lwe_size: LweSize,
    ) -> Ciphertext {
        unchecked_create_trivial_with_lwe_size(
            value,
            lwe_size,
            self.message_modulus,
            self.carry_modulus,
            self.atomic_pattern.kind(),
            self.ciphertext_modulus,
        )
    }

    pub fn unchecked_create_trivial(&self, value: u64) -> Ciphertext {
        let lwe_size = self.atomic_pattern.ciphertext_lwe_dimension().to_lwe_size();

        self.unchecked_create_trivial_with_lwe_size(Cleartext(value), lwe_size)
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u64) {
        let modular_value = value % self.message_modulus.0;

        let encoded = self
            .encoding(PaddingBit::Yes)
            .encode(Cleartext(modular_value));

        trivially_encrypt_lwe_ciphertext(&mut ct.ct, encoded);

        ct.degree = Degree::new(modular_value);
        ct.set_noise_level(NoiseLevel::ZERO, self.max_noise_level);
    }

    pub fn deterministic_execution(&self) -> bool {
        self.atomic_pattern.deterministic_execution()
    }

    fn trivial_pbs_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        #[cfg(feature = "pbs-stats")]
        // We want to count trivial PBS in simulator mode
        // In the non trivial case, this increment is done in the `apply_ms_blind_rotate` function
        let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

        assert_eq!(ct.noise_level(), NoiseLevel::ZERO);
        let modulus_sup = self.message_modulus.0 * self.carry_modulus.0;
        let ct_value = self
            .encoding(PaddingBit::Yes)
            .decode(Plaintext(*ct.ct.get_body().data))
            .0;

        let lut_size = self.atomic_pattern.lookup_table_size();
        let box_size = lut_size.polynomial_size().0 / modulus_sup as usize;
        let result = if ct_value >= modulus_sup {
            // padding bit is 1
            let ct_value = ct_value % modulus_sup;
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut].wrapping_neg()
        } else {
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut]
        };
        *ct.ct.get_mut_body().data = result;
        ct.degree = acc.degree;
    }

    fn trivial_pbs_many_lut(&self, ct: &Ciphertext, lut: &ManyLookupTableOwned) -> Vec<Ciphertext> {
        #[cfg(feature = "pbs-stats")]
        let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

        assert_eq!(ct.noise_level(), NoiseLevel::ZERO);
        let modulus_sup = self.message_modulus.0 * self.carry_modulus.0;
        let ct_value = self
            .encoding(PaddingBit::Yes)
            .decode(Plaintext(*ct.ct.get_body().data))
            .0;

        let lut_size = self.atomic_pattern.lookup_table_size();
        let box_size = lut_size.polynomial_size().0 / modulus_sup as usize;

        let padding_bit_set = ct_value >= modulus_sup;
        let first_result_index_in_lut = {
            let ct_value = ct_value % modulus_sup;
            ct_value as usize * box_size
        };

        let function_count = lut.function_count();
        let mut outputs = Vec::with_capacity(function_count);

        let polynomial_size = lut.acc.polynomial_size();

        for (fn_idx, output_degree) in lut.per_function_output_degree.iter().enumerate() {
            let (index_in_lut, negation_due_to_wrap_around) = {
                let mut index_in_lut =
                    first_result_index_in_lut + fn_idx * lut.sample_extraction_stride;
                let mut negation_due_to_wrap_around = false;

                let cycles = index_in_lut / polynomial_size.0;
                if cycles % 2 == 1 {
                    // We wrapped around an odd number of times
                    negation_due_to_wrap_around = true;
                }

                index_in_lut %= polynomial_size.0;
                (index_in_lut, negation_due_to_wrap_around)
            };
            let has_to_negate = padding_bit_set ^ negation_due_to_wrap_around;
            let result = {
                let mut result = lut.acc.get_body().as_ref()[index_in_lut];
                if has_to_negate {
                    result = result.wrapping_neg();
                }

                result
            };

            let mut shortint_ct = ct.clone();
            *shortint_ct.ct.get_mut_body().data = result;
            shortint_ct.degree = *output_degree;
            outputs.push(shortint_ct);
        }

        outputs
    }
}

impl<AP: AtomicPatternMut> GenericServerKey<AP> {
    pub fn set_deterministic_execution(&mut self, new_deterministic_execution: bool) {
        self.atomic_pattern
            .set_deterministic_execution(new_deterministic_execution);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CiphertextNoiseDegree {
    pub noise_level: NoiseLevel,
    pub degree: Degree,
}

impl CiphertextNoiseDegree {
    pub fn new(noise_level: NoiseLevel, degree: Degree) -> Self {
        Self {
            noise_level,
            degree,
        }
    }
}

impl Ciphertext {
    pub fn noise_degree(&self) -> CiphertextNoiseDegree {
        CiphertextNoiseDegree {
            noise_level: self.noise_level(),
            degree: self.degree,
        }
    }
    pub fn noise_degree_if_bootstrapped(&self) -> CiphertextNoiseDegree {
        CiphertextNoiseDegree {
            noise_level: NoiseLevel::NOMINAL,
            degree: Degree::new(self.degree.get().min(self.message_modulus.0 - 1)),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct SmartCleaningOperation {
    bootstrap_left: bool,
    bootstrap_right: bool,
}

impl SmartCleaningOperation {
    fn number_of_pbs(self) -> usize {
        usize::from(self.bootstrap_left) + usize::from(self.bootstrap_right)
    }
}

impl<AP: AtomicPattern> GenericServerKey<AP> {
    /// Before doing an operations on 2 inputs which validity is described by
    /// `is_operation_possible`, one or both the inputs may need to be cleaned (carry removal and
    /// noise reinitilization) with a PBS
    /// Among possible cleanings this functions returns one of the ones that has the lowest number
    /// of PBS
    pub(crate) fn binary_smart_op_optimal_cleaning_strategy(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        is_operation_possible: impl Fn(&Self, CiphertextNoiseDegree, CiphertextNoiseDegree) -> bool
            + Copy,
    ) -> Option<SmartCleaningOperation> {
        [false, true]
            .into_iter()
            .flat_map(move |bootstrap_left| {
                let left_noise_degree = if bootstrap_left {
                    ct_left.noise_degree_if_bootstrapped()
                } else {
                    ct_left.noise_degree()
                };

                [false, true]
                    .into_iter()
                    .filter_map(move |bootstrap_right| {
                        let right_noise_degree = if bootstrap_right {
                            ct_right.noise_degree_if_bootstrapped()
                        } else {
                            ct_right.noise_degree()
                        };

                        if is_operation_possible(self, left_noise_degree, right_noise_degree) {
                            Some(SmartCleaningOperation {
                                bootstrap_left,
                                bootstrap_right,
                            })
                        } else {
                            None
                        }
                    })
            })
            .min_by_key(|op| op.number_of_pbs())
    }
}

pub(crate) fn apply_ms_blind_rotate<InputScalar, InputCont, OutputScalar, OutputCont>(
    bootstrapping_key: &ShortintBootstrappingKey<InputScalar>,
    lwe_in: &LweCiphertext<InputCont>,
    acc: &mut GlweCiphertext<OutputCont>,
    buffers: &mut ComputationBuffers,
) where
    InputScalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = InputScalar>,
    OutputScalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    let poly_size = acc.polynomial_size();

    let log_modulus = poly_size.to_blind_rotation_input_modulus_log();

    match bootstrapping_key {
        ShortintBootstrappingKey::Classic {
            bsk: fourier_bsk,
            modulus_switch_noise_reduction_key,
        } => {
            let msed = modulus_switch_noise_reduction_key
                .lwe_ciphertext_modulus_switch(lwe_in, log_modulus);

            apply_standard_blind_rotate(fourier_bsk, &msed, acc, buffers);
        }
        ShortintBootstrappingKey::MultiBit {
            fourier_bsk,
            thread_count,
            deterministic_execution,
        } => {
            let grouping_factor = fourier_bsk.grouping_factor();

            let multi_bit_modulus_switched_input = StandardMultiBitModulusSwitchedCt {
                input: lwe_in.as_view(),
                grouping_factor,
                log_modulus,
            };

            apply_multi_bit_blind_rotate(
                &multi_bit_modulus_switched_input,
                acc,
                fourier_bsk,
                *thread_count,
                *deterministic_execution,
            );
        }
    }
}

pub(crate) fn apply_standard_blind_rotate<OutputScalar, OutputCont>(
    fourier_bsk: &FourierLweBootstrapKeyOwned,
    msed_lwe_in: &impl ModulusSwitchedLweCiphertext<usize>,
    acc: &mut GlweCiphertext<OutputCont>,
    buffers: &mut ComputationBuffers,
) where
    OutputScalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    #[cfg(feature = "pbs-stats")]
    let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

    let poly_size = acc.polynomial_size();

    let fft = Fft::new(poly_size);

    let fft = fft.as_view();

    buffers.resize(
        blind_rotate_assign_mem_optimized_requirement::<OutputScalar>(
            acc.glwe_size(),
            poly_size,
            fft,
        )
        .unaligned_bytes_required(),
    );

    blind_rotate_assign_mem_optimized(msed_lwe_in, acc, fourier_bsk, fft, buffers.stack());
}

pub(crate) fn apply_multi_bit_blind_rotate<OutputScalar, OutputCont, KeyCont>(
    multi_bit_modulus_switched_input: &impl MultiBitModulusSwitchedLweCiphertext,
    accumulator: &mut GlweCiphertext<OutputCont>,
    multi_bit_bsk: &FourierLweMultiBitBootstrapKey<KeyCont>,
    thread_count: ThreadCount,
    deterministic_execution: bool,
) where
    OutputScalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64> + Sync,
{
    #[cfg(feature = "pbs-stats")]
    let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

    multi_bit_blind_rotate_assign(
        multi_bit_modulus_switched_input,
        accumulator,
        multi_bit_bsk,
        thread_count,
        deterministic_execution,
    );
}

pub(crate) fn apply_programmable_bootstrap<InputScalar, InputCont, OutputScalar, OutputCont>(
    bootstrapping_key: &ShortintBootstrappingKey<InputScalar>,
    lwe_in: &LweCiphertext<InputCont>,
    lwe_out: &mut LweCiphertext<OutputCont>,
    acc: &GlweCiphertext<Vec<OutputScalar>>,
    buffers: &mut ComputationBuffers,
) where
    InputScalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = InputScalar>,
    OutputScalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    let mut glwe_out: GlweCiphertext<_> = acc.clone();

    apply_ms_blind_rotate(bootstrapping_key, lwe_in, &mut glwe_out, buffers);

    extract_lwe_sample_from_glwe_ciphertext(&glwe_out, lwe_out, MonomialDegree(0));
}

pub(crate) fn apply_programmable_bootstrap_128<InputScalar, InputCont, OutputScalar, OutputCont>(
    bootstrapping_key: &Shortint128BootstrappingKey<InputScalar>,
    lwe_in: &LweCiphertext<InputCont>,
    lwe_out: &mut LweCiphertext<OutputCont>,
    acc: &GlweCiphertext<Vec<OutputScalar>>,
    buffers: &mut ComputationBuffers,
) where
    InputScalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = InputScalar>,
    OutputScalar: UnsignedTorus + CastFrom<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    match bootstrapping_key {
        Shortint128BootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key,
        } => {
            let bsk_glwe_size = bsk.glwe_size();
            let bsk_polynomial_size = bsk.polynomial_size();

            let fft = Fft128::new(bsk_polynomial_size);
            let fft = fft.as_view();

            let mem_requirement =
                blind_rotate_f128_lwe_ciphertext_mem_optimized_requirement::<u128>(
                    bsk_glwe_size,
                    bsk_polynomial_size,
                    fft,
                )
                .unaligned_bytes_required();

            let br_input_modulus_log = bsk.polynomial_size().to_blind_rotation_input_modulus_log();
            let lwe_ciphertext_to_squash_noise = modulus_switch_noise_reduction_key
                .lwe_ciphertext_modulus_switch(lwe_in, br_input_modulus_log);

            buffers.resize(mem_requirement);

            // Also include sample extract
            blind_rotate_f128_lwe_ciphertext_mem_optimized(
                &lwe_ciphertext_to_squash_noise,
                lwe_out,
                acc,
                bsk,
                fft,
                buffers.stack(),
            );
        }
        Shortint128BootstrappingKey::MultiBit {
            bsk,
            thread_count,
            deterministic_execution,
        } => {
            multi_bit_programmable_bootstrap_f128_lwe_ciphertext(
                lwe_in,
                lwe_out,
                acc,
                bsk,
                *thread_count,
                *deterministic_execution,
            );
        }
    }
}

/// Generate a lookup table without any encoding specifications
///
/// It is the responsibility of the function `f` to encode the input cleartexts into valid
/// plaintexts for the parameters in use.
pub(crate) fn generate_lookup_table_no_encode<F>(
    size: LookupTableSize,
    ciphertext_modulus: CiphertextModulus,
    f: F,
) -> GlweCiphertextOwned<u64>
where
    F: Fn(u64) -> u64,
{
    let mut acc = GlweCiphertext::new(
        0,
        size.glwe_size(),
        size.polynomial_size(),
        ciphertext_modulus,
    );
    fill_accumulator_no_encoding(&mut acc, size.polynomial_size(), size.glwe_size(), f);

    acc
}

/// Generate a LUT where the output encoding is identical to the input one
pub fn generate_lookup_table<F>(
    size: LookupTableSize,
    ciphertext_modulus: CiphertextModulus,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    f: F,
) -> LookupTableOwned
where
    F: Fn(u64) -> u64,
{
    generate_lookup_table_with_output_encoding(
        size,
        ciphertext_modulus,
        message_modulus,
        carry_modulus,
        message_modulus,
        carry_modulus,
        f,
    )
}

/// Generate a LUT where the output encoding might be different than the input one
///
/// Caller needs to ensure that the operation applied is coherent from an encoding perspective.
///
/// For example:
///
/// Input encoding has 2 bits and output encoding has 4 bits, applying the identity lut would map
/// the following:
///
/// 0|00|xx -> 0|00|00
/// 0|01|xx -> 0|00|01
/// 0|10|xx -> 0|00|10
/// 0|11|xx -> 0|00|11
///
/// The reason is the identity function is computed in the input space but the scaling is done in
/// the output space, as there are more bits in the output space, the delta is smaller hence the
/// apparent "division" happening.
pub(crate) fn generate_lookup_table_with_output_encoding<F>(
    size: LookupTableSize,
    ciphertext_modulus: CiphertextModulus,
    input_message_modulus: MessageModulus,
    input_carry_modulus: CarryModulus,
    output_message_modulus: MessageModulus,
    output_carry_modulus: CarryModulus,
    f: F,
) -> LookupTableOwned
where
    F: Fn(u64) -> u64,
{
    let mut acc = GlweCiphertext::new(0, size.glwe_size, size.polynomial_size, ciphertext_modulus);
    let max_value = fill_accumulator_with_encoding(
        &mut acc,
        size.polynomial_size(),
        size.glwe_size(),
        input_message_modulus,
        input_carry_modulus,
        output_message_modulus,
        output_carry_modulus,
        f,
    );

    LookupTableOwned {
        acc,
        degree: Degree::new(max_value),
    }
}

#[derive(Copy, Clone)]
pub struct PBSConformanceParams {
    pub in_lwe_dimension: LweDimension,
    pub out_glwe_dimension: GlweDimension,
    pub out_polynomial_size: PolynomialSize,
    pub base_log: DecompositionBaseLog,
    pub level: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_type: PbsTypeConformanceParams,
}

#[derive(Copy, Clone)]
pub enum PbsTypeConformanceParams {
    Classic {
        modulus_switch_noise_reduction: ModulusSwitchType,
    },
    MultiBit {
        lwe_bsk_grouping_factor: LweBskGroupingFactor,
    },
}

impl From<&PBSParameters> for PBSConformanceParams {
    fn from(value: &PBSParameters) -> Self {
        Self {
            in_lwe_dimension: value.lwe_dimension(),
            out_glwe_dimension: value.glwe_dimension(),
            out_polynomial_size: value.polynomial_size(),
            base_log: value.pbs_base_log(),
            level: value.pbs_level(),
            ciphertext_modulus: value.ciphertext_modulus(),
            pbs_type: match value {
                PBSParameters::PBS(classic_pbsparameters) => PbsTypeConformanceParams::Classic {
                    modulus_switch_noise_reduction: classic_pbsparameters
                        .modulus_switch_noise_reduction_params,
                },
                PBSParameters::MultiBitPBS(multi_bit_pbs_parameters) => {
                    PbsTypeConformanceParams::MultiBit {
                        lwe_bsk_grouping_factor: multi_bit_pbs_parameters.grouping_factor,
                    }
                }
            },
        }
    }
}

impl From<&KeySwitch32PBSParameters> for PBSConformanceParams {
    fn from(value: &KeySwitch32PBSParameters) -> Self {
        Self {
            in_lwe_dimension: value.lwe_dimension(),
            out_glwe_dimension: value.glwe_dimension(),
            out_polynomial_size: value.polynomial_size(),
            base_log: value.pbs_base_log(),
            level: value.pbs_level(),
            ciphertext_modulus: value.ciphertext_modulus(),
            pbs_type: PbsTypeConformanceParams::Classic {
                modulus_switch_noise_reduction: value.modulus_switch_noise_reduction_params,
            },
        }
    }
}

impl<InputScalar> ParameterSetConformant for ShortintBootstrappingKey<InputScalar>
where
    InputScalar: UnsignedInteger,
{
    type ParameterSet = PBSConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, &parameter_set.pbs_type) {
            (
                Self::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                },
                PbsTypeConformanceParams::Classic {
                    modulus_switch_noise_reduction,
                },
            ) => {
                let modulus_switch_noise_reduction_key_conformant = match (
                    modulus_switch_noise_reduction_key,
                    modulus_switch_noise_reduction,
                ) {
                    (ModulusSwitchConfiguration::Standard, ModulusSwitchType::Standard) => true,
                    (
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction,
                        ModulusSwitchType::CenteredMeanNoiseReduction,
                    ) => true,
                    (
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ),
                        ModulusSwitchType::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_params,
                        ),
                    ) => {
                        let param = ModulusSwitchNoiseReductionKeyConformanceParams {
                            modulus_switch_noise_reduction_params:
                                *modulus_switch_noise_reduction_params,
                            lwe_dimension: parameter_set.in_lwe_dimension,
                        };

                        modulus_switch_noise_reduction_key.is_conformant(&param)
                    }
                    _ => false,
                };

                let param: LweBootstrapKeyConformanceParams<_> = parameter_set.into();

                bsk.is_conformant(&param) && modulus_switch_noise_reduction_key_conformant
            }
            (
                Self::MultiBit {
                    fourier_bsk,
                    thread_count: _,
                    deterministic_execution: _,
                },
                PbsTypeConformanceParams::MultiBit { .. },
            ) => MultiBitBootstrapKeyConformanceParams::try_from(parameter_set)
                .is_ok_and(|param| fourier_bsk.is_conformant(&param)),
            _ => false,
        }
    }
}

impl ParameterSetConformant for ServerKey {
    type ParameterSet = (AtomicPatternParameters, MaxDegree);

    fn is_conformant(&self, (parameter_set, expected_max_degree): &Self::ParameterSet) -> bool {
        let Self {
            message_modulus,
            atomic_pattern,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
        } = self;

        atomic_pattern.is_conformant(parameter_set)
            && *max_degree == *expected_max_degree
            && *message_modulus == parameter_set.message_modulus()
            && *carry_modulus == parameter_set.carry_modulus()
            && *max_noise_level == parameter_set.max_noise_level()
            && *ciphertext_modulus == parameter_set.ciphertext_modulus()
    }
}

impl StandardServerKeyView<'_> {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.atomic_pattern
            .bootstrapping_key
            .bootstrapping_key_size_elements()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.atomic_pattern
            .bootstrapping_key
            .bootstrapping_key_size_bytes()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.atomic_pattern.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.atomic_pattern.key_switching_key.as_ref())
    }
}

impl StandardServerKey {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.as_view().bootstrapping_key_size_elements()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.as_view().bootstrapping_key_size_bytes()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.as_view().key_switching_key_size_elements()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        self.as_view().key_switching_key_size_bytes()
    }
}
