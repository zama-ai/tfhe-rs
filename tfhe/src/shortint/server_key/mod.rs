//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
mod add;
mod bitwise_op;
mod bivariate_pbs;
mod comp_op;
mod div_mod;
mod mul;
mod neg;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

pub mod compressed;
pub use bivariate_pbs::{
    BivariateLookupTableMutView, BivariateLookupTableOwned, BivariateLookupTableView,
};
pub use compressed::{CompressedServerKey, ShortintCompressedBootstrappingKey};

#[cfg(test)]
mod tests;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    ThreadCount,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::shortint::ciphertext::{Ciphertext, Degree, MaxDegree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::{fill_accumulator, ShortintEngine};
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CiphertextModulus, MessageModulus,
};
use crate::shortint::PBSOrder;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

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

#[derive(Clone, Debug, PartialEq)]
pub enum ShortintBootstrappingKey {
    Classic(FourierLweBootstrapKeyOwned),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
enum SerializableShortintBootstrappingKey<C: Container<Element = concrete_fft::c64>> {
    Classic(FourierLweBootstrapKey<C>),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl Serialize for ShortintBootstrappingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Classic(bsk) => SerializableShortintBootstrappingKey::Classic(bsk.as_view()),
            Self::MultiBit {
                fourier_bsk: bsk,
                deterministic_execution,
                ..
            } => SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk: bsk.as_view(),
                deterministic_execution: *deterministic_execution,
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ShortintBootstrappingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deser_sk = SerializableShortintBootstrappingKey::deserialize(deserializer)?;

        match deser_sk {
            SerializableShortintBootstrappingKey::Classic(bsk) => Ok(Self::Classic(bsk)),
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
                Ok(Self::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                })
            }
        }
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
}

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl ServerKey {
    pub fn conformance_params(&self) -> CiphertextConformanceParams {
        let lwe_dim = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        };

        let ct_params = LweCiphertextParameters {
            lwe_dim,
            ct_modulus: self.ciphertext_modulus,
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
    /// let acc = sks.generate_lookup_table(f);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3**2 mod 4 = 1
    /// assert_eq!(dec, f(msg));
    /// ```
    pub fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let mut acc = GlweCiphertext::new(
            0,
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
            self.ciphertext_modulus,
        );
        let max_value = fill_accumulator(&mut acc, self, f);

        LookupTableOwned {
            acc,
            degree: Degree::new(max_value as usize),
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
    /// let acc = sks.generate_msg_lookup_table(f, ct.message_modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg) % 4);
    /// ```
    pub fn generate_msg_lookup_table<F>(&self, f: F, modulus: MessageModulus) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        self.generate_lookup_table(|x| f(x % modulus.0 as u64) % modulus.0 as u64)
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
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x -> x*x*x mod 4
    /// let acc = sks.generate_lookup_table(|x| x * x * x % modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
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
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                // This updates the ciphertext degree
                self.keyswitch_programmable_bootstrap_assign(ct, acc);
            }
            PBSOrder::BootstrapKeyswitch => {
                // This updates the ciphertext degree
                self.programmable_bootstrap_keyswitch_assign(ct, acc);
            }
        };
    }
    /// Applies the given function to the message of a ciphertext
    /// The input is reduced to the message space before the funciton application
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
    /// The input is reduced to the message space before the funciton application
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
        let modulus = ct.message_modulus.0 as u64;

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
        let modular_value = value as usize % self.message_modulus.0;
        self.unchecked_create_trivial(modular_value as u64)
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

        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        let shifted_value = value * delta;

        let encoded = Plaintext(shifted_value);

        let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            lwe_size,
            encoded,
            self.ciphertext_modulus,
        );

        let degree = Degree::new(value as usize);

        Ciphertext::new(
            ct,
            degree,
            NoiseLevel::ZERO,
            self.message_modulus,
            self.carry_modulus,
            self.pbs_order,
        )
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u64) {
        let modular_value = value as usize % self.message_modulus.0;

        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        trivially_encrypt_lwe_ciphertext(&mut ct.ct, encoded);

        ct.degree = Degree::new(modular_value);
        ct.set_noise_level(NoiseLevel::ZERO);
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
        assert_eq!(ct.noise_level(), NoiseLevel::ZERO);
        let modulus_sup = self.message_modulus.0 * self.carry_modulus.0;
        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;
        let ct_value = *ct.ct.get_body().data / delta;

        let box_size = self.bootstrapping_key.polynomial_size().0 / modulus_sup;
        let result = if ct_value >= modulus_sup as u64 {
            // padding bit is 1
            let ct_value = ct_value % modulus_sup as u64;
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut].wrapping_neg()
        } else {
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut]
        };
        *ct.ct.get_mut_body().data = result;
        ct.degree = acc.degree;
    }

    pub(crate) fn keyswitch_programmable_bootstrap_assign(
        &self,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        if ct.is_trivial() {
            self.trivial_pbs_assign(ct, acc);
            return;
        }

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &ct.ct,
                &mut ciphertext_buffers.buffer_lwe_after_ks,
            );

            match &self.bootstrapping_key {
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

                    // Compute a bootstrap
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        &mut ct.ct,
                        &acc.acc,
                        fourier_bsk,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                } => {
                    if *deterministic_execution {
                        multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                            &ciphertext_buffers.buffer_lwe_after_ks,
                            &mut ct.ct,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    } else {
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &ciphertext_buffers.buffer_lwe_after_ks,
                            &mut ct.ct,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    }
                }
            };
        });

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }

    pub(crate) fn programmable_bootstrap_keyswitch_assign(
        &self,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        if ct.is_trivial() {
            self.trivial_pbs_assign(ct, acc);
            return;
        }

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);

            match &self.bootstrapping_key {
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

                    // Compute a bootstrap
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        &acc.acc,
                        fourier_bsk,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                } => {
                    if *deterministic_execution {
                        multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                            &ct.ct,
                            &mut ciphertext_buffers.buffer_lwe_after_pbs,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    } else {
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &ct.ct,
                            &mut ciphertext_buffers.buffer_lwe_after_pbs,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    }
                }
            };

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &ciphertext_buffers.buffer_lwe_after_pbs,
                &mut ct.ct,
            );
        });

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(compressed_server_key: CompressedServerKey) -> Self {
        let CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            ciphertext_modulus,
            pbs_order,
        } = compressed_server_key;

        let (key_switching_key, bootstrapping_key) = rayon::join(
            || key_switching_key.par_decompress_into_lwe_keyswitch_key(),
            || match bootstrapping_key {
                ShortintCompressedBootstrappingKey::Classic(bootstrapping_key) => {
                    let standard_bootstrapping_key =
                        bootstrapping_key.par_decompress_into_lwe_bootstrap_key();

                    let mut bootstrapping_key = FourierLweBootstrapKeyOwned::new(
                        standard_bootstrapping_key.input_lwe_dimension(),
                        standard_bootstrapping_key.glwe_size(),
                        standard_bootstrapping_key.polynomial_size(),
                        standard_bootstrapping_key.decomposition_base_log(),
                        standard_bootstrapping_key.decomposition_level_count(),
                    );

                    par_convert_standard_lwe_bootstrap_key_to_fourier(
                        &standard_bootstrapping_key,
                        &mut bootstrapping_key,
                    );

                    ShortintBootstrappingKey::Classic(bootstrapping_key)
                }
                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bootstrapping_key,
                    deterministic_execution,
                } => {
                    let standard_bootstrapping_key =
                        bootstrapping_key.par_decompress_into_lwe_multi_bit_bootstrap_key();

                    let mut bootstrapping_key = FourierLweMultiBitBootstrapKeyOwned::new(
                        standard_bootstrapping_key.input_lwe_dimension(),
                        standard_bootstrapping_key.glwe_size(),
                        standard_bootstrapping_key.polynomial_size(),
                        standard_bootstrapping_key.decomposition_base_log(),
                        standard_bootstrapping_key.decomposition_level_count(),
                        standard_bootstrapping_key.grouping_factor(),
                    );

                    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(
                        &standard_bootstrapping_key,
                        &mut bootstrapping_key,
                    );

                    let thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                        engine.get_thread_count_for_multi_bit_pbs(
                            standard_bootstrapping_key.input_lwe_dimension(),
                            standard_bootstrapping_key.glwe_size().to_glwe_dimension(),
                            standard_bootstrapping_key.polynomial_size(),
                            standard_bootstrapping_key.decomposition_base_log(),
                            standard_bootstrapping_key.decomposition_level_count(),
                            standard_bootstrapping_key.grouping_factor(),
                        )
                    });

                    ShortintBootstrappingKey::MultiBit {
                        fourier_bsk: bootstrapping_key,
                        thread_count,
                        deterministic_execution,
                    }
                }
            },
        );

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(message_modulus, carry_modulus);

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
}

#[derive(Copy, Clone)]
pub struct CiphertextNoiseDegree {
    pub noise_level: NoiseLevel,
    pub degree: Degree,
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
