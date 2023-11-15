//! Welcome the the `concrete-float` documentation!
//!
//! # Description
//!
//! This library makes it possible to execute floating point operations.
//!
//! It allows to execute a floating point circuit on an untrusted server because both circuit inputs
//! and outputs are kept private.
//!
//! Data is encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts
extern crate core;

pub mod ciphertext;
pub mod client_key;
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod server_key;

pub use ciphertext::Ciphertext;
pub use client_key::ClientKey;
pub use server_key::{CheckError, ServerKey};



/// Generate a couple of client and server keys with given parameters
///
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is meant to
///   be published (the client sends it to the server).
///
pub fn gen_keys(
    parameters_set: crate::shortint::parameters::WopbsParameters,
) -> (ClientKey, ServerKey) {
    let pbs_params = crate::shortint::parameters::ClassicPBSParameters {
        lwe_dimension: parameters_set.lwe_dimension,
        glwe_dimension: parameters_set.glwe_dimension,
        polynomial_size: parameters_set.polynomial_size,
        lwe_modular_std_dev: parameters_set.lwe_modular_std_dev,
        glwe_modular_std_dev: parameters_set.glwe_modular_std_dev,
        pbs_base_log: parameters_set.pbs_base_log,
        pbs_level: parameters_set.pbs_level,
        ks_base_log: parameters_set.ks_base_log,
        ks_level: parameters_set.ks_level,
        message_modulus: parameters_set.message_modulus,
        carry_modulus: parameters_set.carry_modulus,
        ciphertext_modulus: parameters_set.ciphertext_modulus,
        encryption_key_choice: parameters_set.encryption_key_choice,
    };
    let params = (pbs_params, parameters_set);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    (cks,sks)
}
