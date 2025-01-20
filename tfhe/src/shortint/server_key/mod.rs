//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
mod add;
mod bitwise_op;
mod bivariate_pbs;
mod comp_op;
mod div_mod;
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

pub use bivariate_pbs::{
    BivariateLookupTableMutView, BivariateLookupTableOwned, BivariateLookupTableView,
};
pub use compressed::{CompressedServerKey, ShortintCompressedBootstrappingKey};
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
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::BootstrapKeyConformanceParams;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::core_crypto::prelude::ComputationBuffers;
use crate::shortint::ciphertext::{Ciphertext, Degree, MaxDegree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::{
    fill_accumulator, fill_accumulator_no_encoding, fill_accumulator_with_encoding,
    fill_many_lut_accumulator, ShortintEngine,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CiphertextModulus, MessageModulus,
};
use crate::shortint::{EncryptionKeyChoice, PBSOrder, PaddingBit, ShortintEncoding};
use aligned_vec::ABox;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
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

use super::backward_compatibility::server_key::{
    SerializableShortintBootstrappingKeyVersions, ServerKeyVersions,
};
use super::ciphertext::unchecked_create_trivial_with_lwe_size;
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
#[versionize(convert = "SerializableShortintBootstrappingKey<ABox<[tfhe_fft::c64]>>")]
pub enum ShortintBootstrappingKey {
    Classic(FourierLweBootstrapKeyOwned),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(SerializableShortintBootstrappingKeyVersions)]
pub enum SerializableShortintBootstrappingKey<C: Container<Element = tfhe_fft::c64>> {
    Classic(FourierLweBootstrapKey<C>),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl<C: Container<Element = tfhe_fft::c64>> SerializableShortintBootstrappingKey<C> {
    /// Returns `true` if the serializable shortint bootstrapping key is [`Classic`].
    ///
    /// [`Classic`]: SerializableShortintBootstrappingKey::Classic
    #[must_use]
    pub fn is_classic(&self) -> bool {
        matches!(self, Self::Classic(..))
    }
}

impl<'a> From<&'a ShortintBootstrappingKey>
    for SerializableShortintBootstrappingKey<&'a [tfhe_fft::c64]>
{
    fn from(value: &'a ShortintBootstrappingKey) -> Self {
        match value {
            ShortintBootstrappingKey::Classic(bsk) => Self::Classic(bsk.as_view()),
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

impl From<ShortintBootstrappingKey>
    for SerializableShortintBootstrappingKey<ABox<[tfhe_fft::c64]>>
{
    fn from(value: ShortintBootstrappingKey) -> Self {
        match value {
            ShortintBootstrappingKey::Classic(bsk) => Self::Classic(bsk),
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

impl Serialize for ShortintBootstrappingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializableShortintBootstrappingKey::from(self).serialize(serializer)
    }
}

impl From<SerializableShortintBootstrappingKey<ABox<[tfhe_fft::c64]>>>
    for ShortintBootstrappingKey
{
    fn from(value: SerializableShortintBootstrappingKey<ABox<[tfhe_fft::c64]>>) -> Self {
        match value {
            SerializableShortintBootstrappingKey::Classic(bsk) => Self::Classic(bsk),
            SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                deterministic_execution,
            } => {
                let thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                    engine.get_thread_count_for_multi_bit_pbs(
                        fourier_bsk.input_lwe_dimension(),
                        fourier_bsk.glwe_size().to_glwe_dimension(),
                        fourier_bsk.polynomial_size(),
                        fourier_bsk.decomposition_base_log(),
                        fourier_bsk.decomposition_level_count(),
                        fourier_bsk.grouping_factor(),
                    )
                });
                Self::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for ShortintBootstrappingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deser_sk = SerializableShortintBootstrappingKey::deserialize(deserializer)?;
        Ok(Self::from(deser_sk))
    }
}

impl ShortintBootstrappingKey {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic(inner) => inner.input_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.input_lwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic(inner) => inner.polynomial_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic(inner) => inner.glwe_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.glwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic(inner) => inner.decomposition_base_log(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_base_log(),
        }
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic(inner) => inner.decomposition_level_count(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_level_count(),
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic(inner) => inner.output_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.output_lwe_dimension(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match self {
            Self::Classic(bsk) => bsk.as_view().data().len(),
            Self::MultiBit {
                fourier_bsk: bsk, ..
            } => bsk.as_view().data().len(),
        }
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match self {
            Self::Classic(bsk) => std::mem::size_of_val(bsk.as_view().data()),
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
            Self::Classic(_) => true,
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
            Self::Classic(_) => (),
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
            Self::Classic(_) => (),
            Self::MultiBit {
                fourier_bsk,
                thread_count,
                ..
            } => {
                *thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                    engine.get_thread_count_for_multi_bit_pbs(
                        fourier_bsk.input_lwe_dimension(),
                        fourier_bsk.glwe_size().to_glwe_dimension(),
                        fourier_bsk.polynomial_size(),
                        fourier_bsk.decomposition_base_log(),
                        fourier_bsk.decomposition_level_count(),
                        fourier_bsk.grouping_factor(),
                    )
                })
            }
        }
    }
}

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(ServerKeyVersions)]
pub struct ServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    // Modulus use for computations on the ciphertext
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
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

    pub fn ciphertext_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        }
    }

    /// Deconstruct a [`ServerKey`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        LweKeyswitchKeyOwned<u64>,
        ShortintBootstrappingKey,
        MessageModulus,
        CarryModulus,
        MaxDegree,
        MaxNoiseLevel,
        CiphertextModulus,
        PBSOrder,
    ) {
        let Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        } = self;

        (
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        )
    }

    /// Construct a [`ServerKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the constituents are not compatible with each others.
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw_parts(
        key_switching_key: LweKeyswitchKeyOwned<u64>,
        bootstrapping_key: ShortintBootstrappingKey,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        max_degree: MaxDegree,
        max_noise_level: MaxNoiseLevel,
        ciphertext_modulus: CiphertextModulus,
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

        assert_eq!(
            key_switching_key.ciphertext_modulus(),
            ciphertext_modulus,
            "Mismatch between the LweKeyswitchKey CiphertextModulus ({:?}) \
            and the provided CiphertextModulus ({:?})",
            key_switching_key.ciphertext_modulus(),
            ciphertext_modulus
        );

        let max_max_degree = MaxDegree::from_msg_carry_modulus(message_modulus, carry_modulus);

        assert!(
            max_degree.get() <= max_max_degree.get(),
            "Maximum valid MaxDegree is {max_max_degree:?}, got ({max_degree:?})"
        );

        Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        }
    }

    pub fn conformance_params(&self) -> CiphertextConformanceParams {
        let lwe_dim = self.ciphertext_lwe_dimension();

        let ms_decompression_method = match &self.bootstrapping_key {
            ShortintBootstrappingKey::Classic(_) => MsDecompressionType::ClassicPbs,
            ShortintBootstrappingKey::MultiBit { fourier_bsk, .. } => {
                MsDecompressionType::MultiBitPbs(fourier_bsk.grouping_factor())
            }
        };

        let ct_params = LweCiphertextParameters {
            lwe_dim,
            ct_modulus: self.ciphertext_modulus,
            ms_decompression_method,
        };

        CiphertextConformanceParams {
            ct_params,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: Degree::new(self.message_modulus.0 - 1),
            pbs_order: self.pbs_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }

    pub(crate) fn encoding(&self, padding_bit: PaddingBit) -> ShortintEncoding {
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
        generate_lookup_table(
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            f,
        )
    }

    pub(crate) fn generate_lookup_table_no_encode<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let mut acc = GlweCiphertext::new(
            0,
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
            self.ciphertext_modulus,
        );
        fill_accumulator_no_encoding(
            &mut acc,
            self.bootstrapping_key.polynomial_size(),
            self.bootstrapping_key.glwe_size(),
            f,
        );

        LookupTableOwned {
            acc,
            // We should not rely on the degree in this case
            // The degree should be set manually on the outputs of PBS by this LUT
            degree: Degree::new(self.message_modulus.0 * self.carry_modulus.0 * 2),
        }
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    ///     let msg = 3;
    ///
    ///     let ct = cks.encrypt(msg);
    ///
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 4;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 4;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (res, function) in vec_res.iter().zip(functions) {
    ///         let dec = cks.decrypt(res);
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    ///     let msg = 3;
    ///
    ///     let ct = cks.encrypt(msg);
    ///
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 4;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 4;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (res, function) in vec_res.iter().zip(functions) {
    ///         let dec = cks.decrypt(res);
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// ```
    pub fn generate_many_lookup_table(
        &self,
        functions: &[&dyn Fn(u64) -> u64],
    ) -> ManyLookupTableOwned {
        let mut acc = GlweCiphertext::new(
            0,
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
            self.ciphertext_modulus,
        );
        let (input_max_degree, sample_extraction_stride, per_function_output_degree) =
            fill_many_lut_accumulator(
                &mut acc,
                self.bootstrapping_key.polynomial_size(),
                self.bootstrapping_key.glwe_size(),
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
    /// let modulus = cks.parameters.message_modulus().0;
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

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);
            match self.pbs_order {
                PBSOrder::KeyswitchBootstrap => {
                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_ks,
                    );

                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        &mut ct.ct,
                        &acc.acc,
                        buffers,
                    );
                }
                PBSOrder::BootstrapKeyswitch => {
                    apply_programmable_bootstrap(
                        &self.bootstrapping_key,
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        &acc.acc,
                        buffers,
                    );

                    keyswitch_lwe_ciphertext(
                        &self.key_switching_key,
                        &ciphertext_buffers.buffer_lwe_after_pbs,
                        &mut ct.ct,
                    );
                }
            }
        });

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level);
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    ///     let msg = 3;
    ///
    ///     let ct = cks.encrypt(msg);
    ///
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 4;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 4;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (res, function) in vec_res.iter().zip(functions) {
    ///         let dec = cks.decrypt(res);
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// {
    ///     // Generate the client key and the server key:
    ///     let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    ///     let msg = 3;
    ///
    ///     let ct = cks.encrypt(msg);
    ///
    ///     // Generate the lookup table for the functions
    ///     // f1: x -> x*x mod 4
    ///     // f2: x -> count_ones(x as binary) mod 4
    ///     let f1 = |x: u64| x.pow(2) % 4;
    ///     let f2 = |x: u64| x.count_ones() as u64 % 4;
    ///     // Easy to use for generation
    ///     let luts = sks.generate_many_lookup_table(&[&f1, &f2]);
    ///     let vec_res = sks.apply_many_lookup_table(&ct, &luts);
    ///
    ///     // Need to manually help Rust to iterate over them easily
    ///     let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2];
    ///     for (res, function) in vec_res.iter().zip(functions) {
    ///         let dec = cks.decrypt(res);
    ///         assert_eq!(dec, function(msg));
    ///     }
    /// }
    /// ```
    pub fn apply_many_lookup_table(
        &self,
        ct: &Ciphertext,
        acc: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.keyswitch_programmable_bootstrap_many_lut(ct, acc),
            PBSOrder::BootstrapKeyswitch => self.programmable_bootstrap_keyswitch_many_lut(ct, acc),
        }
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
            self.pbs_order,
            self.ciphertext_modulus,
        )
    }

    pub fn unchecked_create_trivial(&self, value: u64) -> Ciphertext {
        let lwe_size = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                self.bootstrapping_key.output_lwe_dimension().to_lwe_size()
            }
            PBSOrder::BootstrapKeyswitch => {
                self.bootstrapping_key.input_lwe_dimension().to_lwe_size()
            }
        };

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

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.bootstrapping_key_size_elements()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.bootstrapping_key.bootstrapping_key_size_bytes()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.key_switching_key.as_ref())
    }

    pub fn deterministic_pbs_execution(&self) -> bool {
        self.bootstrapping_key.deterministic_pbs_execution()
    }

    pub fn set_deterministic_pbs_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution);
    }

    fn trivial_pbs_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        #[cfg(feature = "pbs-stats")]
        // We want to count trivial PBS in simulator mode
        // In the non trivial case, this increment is done in the `apply_blind_rotate` function
        let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

        assert_eq!(ct.noise_level(), NoiseLevel::ZERO);
        let modulus_sup = self.message_modulus.0 * self.carry_modulus.0;
        let ct_value = self
            .encoding(PaddingBit::Yes)
            .decode(Plaintext(*ct.ct.get_body().data))
            .0;

        let box_size = self.bootstrapping_key.polynomial_size().0 / modulus_sup as usize;
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

        let box_size = self.bootstrapping_key.polynomial_size().0 / modulus_sup as usize;

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

    pub(crate) fn keyswitch_programmable_bootstrap_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        if ct.is_trivial() {
            return self.trivial_pbs_many_lut(ct, lut);
        }

        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &ct.ct,
                &mut ciphertext_buffers.buffer_lwe_after_ks,
            );

            apply_blind_rotate(
                &self.bootstrapping_key,
                &ciphertext_buffers.buffer_lwe_after_ks.as_view(),
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
            output_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level);
            outputs.push(output_shortint_ct);
        }

        outputs
    }

    pub(crate) fn programmable_bootstrap_keyswitch_many_lut(
        &self,
        ct: &Ciphertext,
        lut: &ManyLookupTableOwned,
    ) -> Vec<Ciphertext> {
        if ct.is_trivial() {
            return self.trivial_pbs_many_lut(ct, lut);
        }

        let mut acc = lut.acc.clone();

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (_, buffers) = engine.get_buffers(self);

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
            output_shortint_ct.set_noise_level(NoiseLevel::NOMINAL, self.max_noise_level);
            outputs.push(output_shortint_ct);
        }

        outputs
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

impl ServerKey {
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

pub(crate) fn apply_blind_rotate<Scalar, InputCont, OutputCont>(
    bootstrapping_key: &ShortintBootstrappingKey,
    in_buffer: &LweCiphertext<InputCont>,
    acc: &mut GlweCiphertext<OutputCont>,
    buffers: &mut ComputationBuffers,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    #[cfg(feature = "pbs-stats")]
    let _ = PBS_COUNT.fetch_add(1, Ordering::Relaxed);

    match bootstrapping_key {
        ShortintBootstrappingKey::Classic(fourier_bsk) => {
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

            // Compute the blind rotation
            blind_rotate_assign_mem_optimized(in_buffer, acc, fourier_bsk, fft, stack);
        }
        ShortintBootstrappingKey::MultiBit {
            fourier_bsk,
            thread_count,
            deterministic_execution,
        } => {
            multi_bit_blind_rotate_assign(
                in_buffer,
                acc,
                fourier_bsk,
                *thread_count,
                *deterministic_execution,
            );
        }
    };
}

pub(crate) fn apply_programmable_bootstrap<InputCont, OutputCont>(
    bootstrapping_key: &ShortintBootstrappingKey,
    in_buffer: &LweCiphertext<InputCont>,
    out_buffer: &mut LweCiphertext<OutputCont>,
    acc: &GlweCiphertext<Vec<u64>>,
    buffers: &mut ComputationBuffers,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
{
    let mut glwe_out: GlweCiphertext<_> = acc.clone();

    apply_blind_rotate(bootstrapping_key, in_buffer, &mut glwe_out, buffers);

    extract_lwe_sample_from_glwe_ciphertext(&glwe_out, out_buffer, MonomialDegree(0));
}

pub fn generate_lookup_table<F>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    f: F,
) -> LookupTableOwned
where
    F: Fn(u64) -> u64,
{
    let mut acc = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);
    let max_value = fill_accumulator(
        &mut acc,
        polynomial_size,
        glwe_size,
        message_modulus,
        carry_modulus,
        f,
    );

    LookupTableOwned {
        acc,
        degree: Degree::new(max_value),
    }
}

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
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_lookup_table_with_encoding<F>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
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
    let mut acc = GlweCiphertext::new(0, glwe_size, polynomial_size, ciphertext_modulus);
    let max_value = fill_accumulator_with_encoding(
        &mut acc,
        polynomial_size,
        glwe_size,
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
pub struct PBSConformanceParameters {
    pub in_lwe_dimension: LweDimension,
    pub out_glwe_dimension: GlweDimension,
    pub out_polynomial_size: PolynomialSize,
    pub base_log: DecompositionBaseLog,
    pub level: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus,
    pub multi_bit: Option<LweBskGroupingFactor>,
}

impl From<&PBSParameters> for PBSConformanceParameters {
    fn from(value: &PBSParameters) -> Self {
        Self {
            in_lwe_dimension: value.lwe_dimension(),
            out_glwe_dimension: value.glwe_dimension(),
            out_polynomial_size: value.polynomial_size(),
            base_log: value.pbs_base_log(),
            level: value.pbs_level(),
            ciphertext_modulus: value.ciphertext_modulus(),
            multi_bit: match value {
                PBSParameters::PBS(_) => None,
                PBSParameters::MultiBitPBS(multi_bit_pbs_parameters) => {
                    Some(multi_bit_pbs_parameters.grouping_factor)
                }
            },
        }
    }
}

impl ParameterSetConformant for ShortintBootstrappingKey {
    type ParameterSet = PBSConformanceParameters;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        match (self, parameter_set.multi_bit) {
            (Self::Classic(a), None) => {
                let param: BootstrapKeyConformanceParams = parameter_set.into();

                a.is_conformant(&param)
            }
            (
                Self::MultiBit {
                    fourier_bsk,
                    thread_count: _,
                    deterministic_execution: _,
                },
                Some(_grouping_factor),
            ) => {
                let param: MultiBitBootstrapKeyConformanceParams =
                    parameter_set.try_into().unwrap();

                fourier_bsk.is_conformant(&param)
            }
            _ => false,
        }
    }
}

impl ParameterSetConformant for ServerKey {
    type ParameterSet = (PBSParameters, MaxDegree);

    fn is_conformant(&self, (parameter_set, expected_max_degree): &Self::ParameterSet) -> bool {
        let Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
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

        pbs_key_ok
            && ks_key_ok
            && pbs_order_ok
            && *max_degree == *expected_max_degree
            && *message_modulus == parameter_set.message_modulus()
            && *carry_modulus == parameter_set.carry_modulus()
            && *max_noise_level == parameter_set.max_noise_level()
            && *ciphertext_modulus == parameter_set.ciphertext_modulus()
    }
}
