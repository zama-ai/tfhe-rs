//! # Description
//!
//! This library makes it possible to execute modular operations over encrypted short integer.
//!
//! It allows to execute an integer circuit on an untrusted server because both circuit inputs and
//! outputs are kept private.
//!
//! Data are encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts.
//!
//! The server however, has to know the integer circuit to be evaluated.
//! At the end of the computation, the server returns the encryption of the result to the user.
//!
//! # Keys
//!
//! This crates exposes two type of keys:
//! * The [`ClientKey`](crate::shortint::client_key::ClientKey) is used to encrypt and decrypt and
//!   has to be kept secret;
//! * The [`ServerKey`](crate::shortint::server_key::ServerKey) is used to perform homomorphic
//!   operations on the server side and it is meant to be published (the client sends it to the
//!   server).
//!
//!
//! # Quick Example
//!
//! The following piece of code shows how to generate keys and run a small integer circuit
//! homomorphically.
//!
//! ```rust
//! use tfhe::shortint::{gen_keys, Parameters};
//!
//! // We generate a set of client/server keys, using the default parameters:
//! let (mut client_key, mut server_key) = gen_keys(Parameters::default());
//!
//! let msg1 = 1;
//! let msg2 = 0;
//!
//! // We use the client key to encrypt two messages:
//! let ct_1 = client_key.encrypt(msg1);
//! let ct_2 = client_key.encrypt(msg2);
//!
//! // We use the server public key to execute an integer circuit:
//! let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);
//!
//! // We use the client key to decrypt the output of the circuit:
//! let output = client_key.decrypt(&ct_3);
//! assert_eq!(output, 1);
//! ```
pub mod ciphertext;
pub mod client_key;
pub mod engine;
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod prelude;
pub mod public_key;
pub mod server_key;
#[cfg(not(feature = "__wasm_api"))]
pub mod wopbs;

pub use ciphertext::Ciphertext;
pub use client_key::ClientKey;
pub use parameters::Parameters;
pub use public_key::{CompressedPublicKey, PublicKey};
pub use server_key::{CheckError, CompressedServerKey, ServerKey};

/// Generate a couple of client and server keys.
///
/// # Example
///
/// Generating a pair of [ClientKey] and [ServerKey] using the default parameters.
///
/// ```rust
/// use tfhe::shortint::gen_keys;
///
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys(Default::default());
/// ```
pub fn gen_keys(parameters_set: Parameters) -> (ClientKey, ServerKey) {
    let cks = ClientKey::new(parameters_set);
    let sks = ServerKey::new(&cks);

    (cks, sks)
}
