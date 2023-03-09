//! # Description
//!
//! This library makes it possible to execute modular operations over encrypted integer.
//!
//! It allows to execute an integer circuit on an untrusted server because both circuit inputs
//! outputs are kept private.
//!
//! Data are encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts
//!
//! # Quick Example
//!
//! The following piece of code shows how to generate keys and run a integer circuit
//! homomorphically.
//!
//! ```rust
//! use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
//! use tfhe::integer::gen_keys_radix;
//!
//! //4 blocks for the radix decomposition
//! let number_of_blocks = 4;
//! // Modulus = (2^2)*4 = 2^8 (from the parameters chosen and the number of blocks
//! let modulus = 1 << 8;
//!
//! // Generation of the client/server keys, using the default parameters:
//! let (mut client_key, mut server_key) =
//!     gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, number_of_blocks);
//!
//! let msg1 = 153;
//! let msg2 = 125;
//!
//! // Encryption of two messages using the client key:
//! let ct_1 = client_key.encrypt(msg1);
//! let ct_2 = client_key.encrypt(msg2);
//!
//! // Homomorphic evaluation of an integer circuit (here, an addition) using the server key:
//! let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);
//!
//! // Decryption of the ciphertext using the client key:
//! let output = client_key.decrypt(&ct_3);
//! assert_eq!(output, (msg1 + msg2) % modulus);
//! ```
//!
//! # Warning
//! This uses cryptographic parameters from the `concrete-shortint` crates.
//! Currently, the radix approach is only compatible with parameter sets such
//! that the message and carry buffers have the same size.
extern crate core;

#[cfg(test)]
#[macro_use]
mod tests;
mod encryption;

pub mod ciphertext;
pub mod client_key;
#[cfg(any(test, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod public_key;
pub mod server_key;
pub mod u256;
pub mod wopbs;

pub use ciphertext::{CrtCiphertext, IntegerCiphertext, RadixCiphertext};
pub use client_key::{ClientKey, CrtClientKey, RadixClientKey};
pub use public_key::{CompressedPublicKey, PublicKey};
pub use server_key::{CheckError, ServerKey};
pub use u256::U256;

/// Generate a couple of client and server keys with given parameters
///
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is meant to
///   be published (the client sends it to the server).
///
/// ```rust
/// use tfhe::integer::gen_keys;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
///
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys(&PARAM_MESSAGE_2_CARRY_2);
/// ```
pub fn gen_keys(
    parameters_set: &crate::shortint::parameters::Parameters,
) -> (ClientKey, ServerKey) {
    #[cfg(any(test, feature = "internal-keycache"))]
    {
        keycache::KEY_CACHE.get_from_params(*parameters_set)
    }
    #[cfg(all(not(test), not(feature = "internal-keycache")))]
    {
        let cks = ClientKey::new(*parameters_set);
        let sks = ServerKey::new(&cks);

        (cks, sks)
    }
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys], this returns a [RadixClientKey]
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
///
/// // generate the client key and the server key:
/// let num_blocks = 4;
/// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
/// ```
pub fn gen_keys_radix(
    parameters_set: &crate::shortint::parameters::Parameters,
    num_blocks: usize,
) -> (RadixClientKey, ServerKey) {
    let (cks, sks) = gen_keys(parameters_set);

    (RadixClientKey::from((cks, num_blocks)), sks)
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys], this returns a [CrtClientKey]
///
/// ```rust
/// use tfhe::integer::gen_keys_crt;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
///
/// // generate the client key and the server key:
/// let basis = vec![2, 3, 5];
/// let (cks, sks) = gen_keys_crt(&PARAM_MESSAGE_2_CARRY_2, basis);
/// ```
pub fn gen_keys_crt(
    parameters_set: &crate::shortint::parameters::Parameters,
    basis: Vec<u64>,
) -> (CrtClientKey, ServerKey) {
    let (cks, sks) = gen_keys(parameters_set);

    (CrtClientKey::from((cks, basis)), sks)
}
