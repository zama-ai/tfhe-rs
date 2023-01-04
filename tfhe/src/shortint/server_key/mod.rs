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
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

pub mod compressed;
pub use compressed::CompressedServerKey;

#[cfg(test)]
mod tests;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKeyOwned;
use crate::shortint::ciphertext::Ciphertext;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};

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

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: FourierLweBootstrapKeyOwned,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
}

impl ServerKey {
    /// Generate a server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    /// use tfhe::shortint::{gen_keys, ServerKey};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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

    /// Constructs the accumulator given a function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the accumulator for the function f: x -> x^2 mod 2^2
    /// let f = |x| x ^ 2 % 4;
    ///
    /// let acc = sks.generate_accumulator(f);
    /// let ct_res = sks.keyswitch_programmable_bootstrap(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg));
    /// ```
    pub fn generate_accumulator<F>(&self, f: F) -> GlweCiphertextOwned<u64>
    where
        F: Fn(u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.generate_accumulator(self, f).unwrap()
        })
    }

    /// Constructs the accumulator for a given bivariate function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 3;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(0);
    /// // Generate the accumulator for the function f: x -> x^2 mod 2^2
    /// let f = |x, y| (x + y) ^ 2 % 4;
    ///
    /// let acc = sks.generate_accumulator_bivariate(f);
    /// let ct_res = sks.keyswitch_programmable_bootstrap_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg, 0));
    /// ```
    pub fn generate_accumulator_bivariate<F>(&self, f: F) -> GlweCiphertextOwned<u64>
    where
        F: Fn(u64, u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.generate_accumulator_bivariate(self, f).unwrap()
        })
    }

    /// Compute a keyswitch and a bootstrap, returning a new ciphertext with empty
    /// carry bits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let ct_res = sks.keyswitch_bootstrap(&ct_res);
    ///
    /// let ct_carry = sks.carry_extract(&ct_res);
    /// let carry = cks.decrypt(&ct_carry);
    /// assert_eq!(carry, 0);
    ///
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(clear, (3 + 2) % 4);
    /// ```
    pub fn keyswitch_bootstrap(&self, ct_in: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.keyswitch_bootstrap(self, ct_in).unwrap()
        })
    }

    pub fn keyswitch_bootstrap_assign(&self, ct_in: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.keyswitch_bootstrap_assign(self, ct_in).unwrap()
        })
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg: u64 = 3;
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    ///
    /// // Generate the accumulator for the function f: x -> x^3 mod 2^2
    /// let acc = sks.generate_accumulator_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.keyswitch_programmable_bootstrap_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^3 mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn keyswitch_programmable_bootstrap_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .keyswitch_programmable_bootstrap_bivariate(self, ct_left, ct_right, acc)
                .unwrap()
        })
    }

    pub fn keyswitch_programmable_bootstrap_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .keyswitch_programmable_bootstrap_bivariate_assign(self, ct_left, ct_right, acc)
                .unwrap()
        })
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg: u64 = 3;
    /// let ct = cks.encrypt(msg);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    ///
    /// // Generate the accumulator for the function f: x -> x^3 mod 2^2
    /// let acc = sks.generate_accumulator(|x| x * x * x % modulus);
    /// let ct_res = sks.keyswitch_programmable_bootstrap(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^3 mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn keyswitch_programmable_bootstrap(
        &self,
        ct_in: &Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .keyswitch_programmable_bootstrap(self, ct_in, acc)
                .unwrap()
        })
    }

    pub fn keyswitch_programmable_bootstrap_assign(
        &self,
        ct_in: &mut Ciphertext,
        acc: &GlweCiphertextOwned<u64>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .keyswitch_programmable_bootstrap_assign(self, ct_in, acc)
                .unwrap()
        })
    }

    /// Generic programmable bootstrap where messages are concatenated
    /// into one ciphertext to compute bivariate functions.
    /// This is used to apply many binary operations (comparisons, multiplications, division).
    pub fn unchecked_functional_bivariate_pbs<F>(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_functional_bivariate_pbs(self, ct_left, ct_right, f)
                .unwrap()
        })
    }

    pub fn unchecked_functional_bivariate_pbs_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64) -> u64,
    {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_functional_bivariate_pbs_assign(self, ct_left, ct_right, f)
                .unwrap()
        })
    }

    /// Verify if a bivariate functional pbs can be applied on ct_left and ct_right.
    pub fn is_functional_bivariate_pbs_possible(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> bool {
        //product of the degree
        let final_degree = ct1.degree.0 * (ct2.degree.0 + 1) + ct2.degree.0;
        final_degree < ct1.carry_modulus.0 * ct1.message_modulus.0
    }

    /// Replace the input encrypted message by the value of its carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
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

    /// Compute a trivial shortint from a given value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    ///
    /// // Trivial encryption
    /// let ct1 = sks.create_trivial(msg);
    ///
    /// let ct_res = cks.decrypt(&ct1);
    /// assert_eq!(1, ct_res);
    /// ```
    pub fn create_trivial(&self, value: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.create_trivial(self, value).unwrap())
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u8) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.create_trivial_assign(self, ct, value).unwrap()
        })
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.as_view().data().as_ref().len()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.bootstrapping_key_size_elements() * std::mem::size_of::<concrete_fft::c64>()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        self.key_switching_key_size_elements() * std::mem::size_of::<u64>()
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
        } = compressed_server_key;

        let key_switching_key = key_switching_key.decompress_into_lwe_keyswitch_key();
        let standard_bootstrapping_key = bootstrapping_key.decompress_into_lwe_bootstrap_key();

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

        Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct SerializableServerKey {
    pub key_switching_key: Vec<u8>,
    pub bootstrapping_key: Vec<u8>,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
}

impl Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key_switching_key =
            bincode::serialize(&self.key_switching_key).map_err(serde::ser::Error::custom)?;
        let bootstrapping_key = bincode::serialize(&self.bootstrapping_key.as_view())
            .map_err(serde::ser::Error::custom)?;

        SerializableServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            max_degree: self.max_degree,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing =
            SerializableServerKey::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        let key_switching_key = bincode::deserialize(thing.key_switching_key.as_slice())
            .map_err(serde::de::Error::custom)?;

        let bootstrapping_key = bincode::deserialize(thing.bootstrapping_key.as_slice())
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus: thing.message_modulus,
            carry_modulus: thing.carry_modulus,
            max_degree: thing.max_degree,
        })
    }
}
