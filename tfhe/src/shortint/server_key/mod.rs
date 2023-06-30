//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
mod add;
mod bitwise_op;
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
use crate::shortint::ciphertext::{Ciphertext, Degree};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, CiphertextModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

use super::PBSOrder;

/// Maximum value that the degree can reach.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct MaxDegree(pub usize);

/// Error returned when the carry buffer is full.
#[derive(Debug)]
pub enum CheckError {
    CarryFull,
}

impl Display for CheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::CarryFull => {
                write!(f, "The carry buffer is full")
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
            ShortintBootstrappingKey::Classic(bsk) => {
                SerializableShortintBootstrappingKey::Classic(bsk.as_view())
            }
            ShortintBootstrappingKey::MultiBit {
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
            SerializableShortintBootstrappingKey::Classic(bsk) => {
                Ok(ShortintBootstrappingKey::Classic(bsk))
            }
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
                Ok(ShortintBootstrappingKey::MultiBit {
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
            ShortintBootstrappingKey::Classic(inner) => inner.input_lwe_dimension(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.input_lwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            ShortintBootstrappingKey::Classic(inner) => inner.polynomial_size(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            ShortintBootstrappingKey::Classic(inner) => inner.glwe_size(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.glwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            ShortintBootstrappingKey::Classic(inner) => inner.decomposition_base_log(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_base_log(),
        }
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            ShortintBootstrappingKey::Classic(inner) => inner.decomposition_level_count(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_level_count(),
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            ShortintBootstrappingKey::Classic(inner) => inner.output_lwe_dimension(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: inner, ..
            } => inner.output_lwe_dimension(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match self {
            ShortintBootstrappingKey::Classic(bsk) => bsk.as_view().data().len(),
            ShortintBootstrappingKey::MultiBit {
                fourier_bsk: bsk, ..
            } => bsk.as_view().data().len(),
        }
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match self {
            ShortintBootstrappingKey::Classic(bsk) => std::mem::size_of_val(bsk.as_view().data()),
            ShortintBootstrappingKey::MultiBit {
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
            ShortintBootstrappingKey::Classic(_) => true,
            ShortintBootstrappingKey::MultiBit {
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
            ShortintBootstrappingKey::Classic(_) => (),
            ShortintBootstrappingKey::MultiBit {
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
    // Modulus use for computations on the ciphertext
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

/// Returns whether it is possible to pack lhs and rhs into a unique
/// ciphertext without exceeding the max storable value using the formula:
/// `unique_ciphertext = (lhs * factor) + rhs`
fn ciphertexts_can_be_packed_without_exceeding_space(
    lhs: &Ciphertext,
    rhs: &Ciphertext,
    factor: usize,
) -> bool {
    let final_degree = (lhs.degree.0 * factor) + rhs.degree.0;
    final_degree < lhs.carry_modulus.0 * lhs.message_modulus.0
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct LookupTable<C: Container<Element = u64>> {
    pub acc: GlweCiphertext<C>,
    pub degree: Degree,
}

pub type LookupTableOwned = LookupTable<Vec<u64>>;
pub type LookupTableMutView<'a> = LookupTable<&'a mut [u64]>;
pub type LookupTableView<'a> = LookupTable<&'a [u64]>;

#[must_use]
pub struct BivariateLookupTable<C: Container<Element = u64>> {
    // A bivariate lookup table is an univariate loolookup table
    // where the message space is shared to encode
    // 2 values
    pub acc: LookupTable<C>,
    // By how much we shift the lhs in the LUT
    pub ct_right_modulus: MessageModulus,
}

pub type BivariateLookupTableOwned = BivariateLookupTable<Vec<u64>>;
pub type BivariateLookupTableMutView<'a> = BivariateLookupTable<&'a mut [u64]>;
pub type BivariateLookupTableView<'a> = BivariateLookupTable<&'a [u64]>;

impl<C: Container<Element = u64>> BivariateLookupTable<C> {
    pub fn is_bivariate_pbs_possible(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> bool {
        ciphertexts_can_be_packed_without_exceeding_space(lhs, rhs, self.ct_right_modulus.0)
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
    pub fn new(cks: &ClientKey) -> ServerKey {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_server_key(cks).unwrap())
    }

    /// Generate a server key with a chosen maximum degree
    pub fn new_with_max_degree(cks: &ClientKey, max_degree: MaxDegree) -> ServerKey {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .new_server_key_with_max_degree(cks, max_degree)
                .unwrap()
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
    /// // Generate the lookup table for the function f: x -> x^2 mod 2^2
    /// let f = |x| x ^ 2 % 4;
    ///
    /// let acc = sks.generate_lookup_table(f);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg));
    /// ```
    pub fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.generate_lookup_table(self, f).unwrap()
        })
    }

    pub fn generate_lookup_table_bivariate_with_factor<F>(
        &self,
        f: F,
        left_message_scaling: MessageModulus,
    ) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .generate_lookup_table_bivariate_with_factor(self, f, left_message_scaling)
                .unwrap()
        })
    }

    /// Constructs the lookup table for a given bivariate function as input.
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
    /// let msg_1 = 3;
    /// let msg_2 = 2;
    ///
    /// let ct1 = cks.encrypt(msg_1);
    /// let mut ct2 = cks.encrypt(msg_2);
    ///
    /// let f = |x, y| (x + y) % 4;
    ///
    /// let acc = sks.generate_lookup_table_bivariate(f);
    /// assert!(acc.is_bivariate_pbs_possible(&ct1, &ct2));
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, f(msg_1, msg_2));
    /// ```
    pub fn generate_lookup_table_bivariate<F>(&self, f: F) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.generate_lookup_table_bivariate(self, f).unwrap()
        })
    }

    /// Compute a keyswitch and a bootstrap, returning a new ciphertext with empty
    /// carry bits.
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
    /// let mut ct1 = cks.encrypt(3);
    /// // |      ct1        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 1   |
    /// let mut ct2 = cks.encrypt(2);
    /// // |      ct2        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// let ct_res = sks.smart_add(&mut ct1, &mut ct2);
    /// // |     ct_res      |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 1  |   0 1   |
    ///
    /// // Get the carry
    /// let ct_carry = sks.carry_extract(&ct_res);
    /// let carry = cks.decrypt(&ct_carry);
    /// assert_eq!(carry, 1);
    ///
    /// let ct_res = sks.clear_carry(&ct_res);
    ///
    /// let ct_carry = sks.carry_extract(&ct_res);
    /// let carry = cks.decrypt(&ct_carry);
    /// assert_eq!(carry, 0);
    ///
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(clear, (3 + 2) % 4);
    /// ```
    pub fn clear_carry(&self, ct_in: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.clear_carry(self, ct_in).unwrap())
    }

    pub fn clear_carry_assign(&self, ct_in: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.clear_carry_assign(self, ct_in).unwrap()
        })
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
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x -> x^3 mod 2^2
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^3 mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn unchecked_apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_apply_lookup_table_bivariate(self, ct_left, ct_right, acc)
                .unwrap()
        })
    }

    pub fn unchecked_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_apply_lookup_table_bivariate_assign(self, ct_left, ct_right, acc)
                .unwrap()
        })
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
    /// let ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x -> x^3 mod 2^2
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^3 mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn smart_apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_apply_lookup_table_bivariate(self, ct_left, ct_right, acc)
                .unwrap()
        })
    }

    pub fn smart_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_apply_lookup_table_bivariate_assign(self, ct_left, ct_right, acc)
                .unwrap()
        })
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
    /// // Generate the lookup table for the function f: x -> x^3 mod 2^2
    /// let acc = sks.generate_lookup_table(|x| x * x * x % modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^3 mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn apply_lookup_table(&self, ct_in: &Ciphertext, acc: &LookupTableOwned) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.apply_lookup_table(self, ct_in, acc).unwrap()
        })
    }

    pub fn apply_lookup_table_assign(&self, ct_in: &mut Ciphertext, acc: &LookupTableOwned) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.apply_lookup_table_assign(self, ct_in, acc).unwrap()
        })
    }

    /// Generic programmable bootstrap where messages are concatenated into one ciphertext to
    /// evaluate a bivariate function. This is used to apply many binary operations (comparisons,
    /// multiplications, division).
    pub fn unchecked_evaluate_bivariate_function<F>(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_evaluate_bivariate_function(self, ct_left, ct_right, f)
                .unwrap()
        })
    }

    pub fn unchecked_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_evaluate_bivariate_function_assign(self, ct_left, ct_right, f)
                .unwrap()
        })
    }

    /// Verify if a functional bivariate pbs can be applied on ct_left and ct_right.
    pub fn is_functional_bivariate_pbs_possible(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> bool {
        ciphertexts_can_be_packed_without_exceeding_space(ct1, ct2, ct2.degree.0 + 1)
    }

    pub fn smart_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_evaluate_bivariate_function_assign(self, ct_left, ct_right, f)
                .unwrap()
        })
    }

    pub fn smart_evaluate_bivariate_function<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_evaluate_bivariate_function(self, ct_left, ct_right, f)
                .unwrap()
        })
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
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.carry_extract_assign(self, ct).unwrap()
        })
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
        ShortintEngine::with_thread_local_mut(|engine| engine.carry_extract(self, ct).unwrap())
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
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.message_extract_assign(self, ct).unwrap()
        })
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
        ShortintEngine::with_thread_local_mut(|engine| engine.message_extract(self, ct).unwrap())
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
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .create_trivial(self, value, self.ciphertext_modulus)
                .unwrap()
        })
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u64) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.create_trivial_assign(self, ct, value).unwrap()
        })
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
            .set_deterministic_pbs_execution(new_deterministic_execution)
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

        let key_switching_key = key_switching_key.decompress_into_lwe_keyswitch_key();
        let bootstrapping_key = match bootstrapping_key {
            ShortintCompressedBootstrappingKey::Classic(bootstrapping_key) => {
                let standard_bootstrapping_key =
                    bootstrapping_key.decompress_into_lwe_bootstrap_key();

                let mut bootstrapping_key = FourierLweBootstrapKeyOwned::new(
                    standard_bootstrapping_key.input_lwe_dimension(),
                    standard_bootstrapping_key.glwe_size(),
                    standard_bootstrapping_key.polynomial_size(),
                    standard_bootstrapping_key.decomposition_base_log(),
                    standard_bootstrapping_key.decomposition_level_count(),
                );

                convert_standard_lwe_bootstrap_key_to_fourier(
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
                    bootstrapping_key.decompress_into_lwe_multi_bit_bootstrap_key();

                let mut bootstrapping_key = FourierLweMultiBitBootstrapKeyOwned::new(
                    standard_bootstrapping_key.input_lwe_dimension(),
                    standard_bootstrapping_key.glwe_size(),
                    standard_bootstrapping_key.polynomial_size(),
                    standard_bootstrapping_key.decomposition_base_log(),
                    standard_bootstrapping_key.decomposition_level_count(),
                    standard_bootstrapping_key.grouping_factor(),
                );

                convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(
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
        };

        Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            ciphertext_modulus,
            pbs_order,
        }
    }
}
