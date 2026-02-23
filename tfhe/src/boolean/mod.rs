//! # Description
//! This library makes it possible to execute boolean gates over encrypted bits.
//! It allows to execute a boolean circuit on an untrusted server because both circuit inputs and
//! outputs are kept private.
//! Data are indeed encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts.
//! The server however has to know the boolean circuit to be evaluated.
//! At the end of the computation, the server returns the encryption of the result to the user.
//!
//!
//!
//! # Quick Example
//!
//! The following piece of code shows how to generate keys and run a small Boolean circuit
//! homomorphically.
//!
//! ```rust
//! use tfhe::boolean::gen_keys;
//! use tfhe::boolean::prelude::*;
//!
//! // We generate a set of client/server keys, using the default parameters:
//! let (client_key, server_key) = gen_keys();
//!
//! // We use the client secret key to encrypt two messages:
//! let ct_1 = client_key.encrypt(true);
//! let ct_2 = client_key.encrypt(false);
//!
//! // We use the server public key to execute a boolean circuit:
//! // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
//! let ct_3 = server_key.not(&ct_2);
//! let ct_4 = server_key.and(&ct_1, &ct_2);
//! let ct_5 = server_key.nand(&ct_3, &ct_4);
//! let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);
//!
//! // We use the client key to decrypt the output of the circuit:
//! let output_1 = client_key.decrypt(&ct_6);
//! assert!(output_1);
//!
//! // It is possible to compute gates with one input unencrypted
//! let ct_7 = server_key.and(&ct_6, true);
//! let output_2 = client_key.decrypt(&ct_7);
//! assert!(output_2);
//!
//! // It is possible to trivially encrypt on the server side
//! // i.e. to not encrypt but still generate a compatible Ciphertext
//! let ct_8 = server_key.trivial_encrypt(false);
//! let ct_9 = server_key.mux(&ct_7, &ct_3, &ct_8);
//! let output_3 = client_key.decrypt(&ct_9);
//! assert!(output_3);
//! ```

use crate::boolean::client_key::ClientKey;
use crate::boolean::parameters::DEFAULT_PARAMETERS;
use crate::boolean::public_key::{CompressedPublicKey, PublicKey};
use crate::boolean::server_key::ServerKey;
#[cfg(test)]
use rand::Rng;

pub mod backward_compatibility;
pub mod ciphertext;
pub mod client_key;
pub mod engine;
pub mod key_switching_key;
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod prelude;
pub mod public_key;
pub mod server_key;

/// The scaling factor used for the plaintext
pub(crate) const PLAINTEXT_LOG_SCALING_FACTOR: usize = 3;

/// The plaintext associated with true: 1/8
pub(crate) const PLAINTEXT_TRUE: u32 = 1 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// The plaintext associated with false: -1/8
pub(crate) const PLAINTEXT_FALSE: u32 = 7 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// tool to generate random booleans
#[cfg(test)]
pub(crate) fn random_boolean() -> bool {
    // create a random generator
    let mut rng = rand::rng();

    // generate a random bit
    let n: u32 = (rng.gen::<u32>()) % 2;

    // convert it to boolean and return
    n != 0
}

/// tool to generate random integers
#[cfg(test)]
pub(crate) fn random_integer() -> u32 {
    // create a random generator
    let mut rng = rand::rng();

    // generate a random u32
    rng.gen::<u32>()
}

/// Generate a couple of client and server keys with the default cryptographic parameters:
/// `DEFAULT_PARAMETERS`.
/// The client is the one generating both keys.
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is meant to
///   be published (the client sends it to the server).
///
/// ```rust
/// use tfhe::boolean::gen_keys;
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys();
/// ```
pub fn gen_keys() -> (ClientKey, ServerKey) {
    // generate the client key
    let cks = ClientKey::new(&DEFAULT_PARAMETERS);

    // generate the server key
    let sks = ServerKey::new(&cks);

    // return
    (cks, sks)
}
