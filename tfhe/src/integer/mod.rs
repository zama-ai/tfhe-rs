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
//! use tfhe::integer::gen_keys_radix;
//! use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
//!
//! //4 blocks for the radix decomposition
//! let number_of_blocks = 4;
//! // Modulus = (2^2)*4 = 2^8 (from the parameters chosen and the number of blocks
//! let modulus = 1 << 8;
//!
//! // Generation of the client/server keys, using the default parameters:
//! let (mut client_key, mut server_key) =
//!     gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, number_of_blocks);
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
pub mod block_decomposition;
pub(crate) mod encryption;

pub mod bigint;
pub mod ciphertext;
pub mod client_key;
pub mod key_switching_key;
#[cfg(any(test, feature = "internal-keycache"))]
pub mod keycache;
pub mod parameters;
pub mod public_key;
pub mod server_key;
pub mod wopbs;

pub use bigint::u256::U256;
pub use bigint::u512::U512;
pub use ciphertext::{CrtCiphertext, IntegerCiphertext, RadixCiphertext};
pub use client_key::{ClientKey, CrtClientKey, RadixClientKey};
pub use public_key::{CompressedCompactPublicKey, CompressedPublicKey, PublicKey};
pub use server_key::{CheckError, CompressedServerKey, ServerKey};

/// Generate a couple of client and server keys with given parameters
///
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is meant to
///   be published (the client sends it to the server).
///
/// ```rust
/// use tfhe::integer::gen_keys;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
/// ```
pub fn gen_keys<P>(parameters_set: P) -> (ClientKey, ServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let shortint_parameters_set: crate::shortint::parameters::ShortintParameterSet =
        parameters_set.try_into().unwrap();

    let is_wopbs_only_params = shortint_parameters_set.wopbs_only();

    // TODO
    // Manually manage the wopbs only case as a workaround pending wopbs rework
    let shortint_parameters_set = if is_wopbs_only_params {
        let wopbs_params = shortint_parameters_set.wopbs_parameters().unwrap();
        let pbs_params = crate::shortint::parameters::ClassicPBSParameters {
            lwe_dimension: wopbs_params.lwe_dimension,
            glwe_dimension: wopbs_params.glwe_dimension,
            polynomial_size: wopbs_params.polynomial_size,
            lwe_modular_std_dev: wopbs_params.lwe_modular_std_dev,
            glwe_modular_std_dev: wopbs_params.glwe_modular_std_dev,
            pbs_base_log: wopbs_params.pbs_base_log,
            pbs_level: wopbs_params.pbs_level,
            ks_base_log: wopbs_params.ks_base_log,
            ks_level: wopbs_params.ks_level,
            message_modulus: wopbs_params.message_modulus,
            carry_modulus: wopbs_params.carry_modulus,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        crate::shortint::parameters::ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
            pbs_params,
            wopbs_params,
        ))
        .unwrap()
    } else {
        shortint_parameters_set
    };

    let gen_keys_inner = |parameters_set| {
        let cks = ClientKey::new(parameters_set);
        let sks = ServerKey::new(&cks);

        (cks, sks)
    };

    #[cfg(any(test, feature = "internal-keycache"))]
    {
        if is_wopbs_only_params {
            // TODO
            // Keycache is broken for the wopbs only case, so generate keys instead
            gen_keys_inner(shortint_parameters_set)
        } else {
            keycache::KEY_CACHE.get_from_params(shortint_parameters_set.pbs_parameters().unwrap())
        }
    }
    #[cfg(all(not(test), not(feature = "internal-keycache")))]
    {
        gen_keys_inner(shortint_parameters_set)
    }
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys], this returns a [RadixClientKey]
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // generate the client key and the server key:
/// let num_blocks = 4;
/// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
/// ```
pub fn gen_keys_radix<P>(parameters_set: P, num_blocks: usize) -> (RadixClientKey, ServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let (cks, sks) = gen_keys(parameters_set);

    (RadixClientKey::from((cks, num_blocks)), sks)
}

/// Generate a couple of client and server keys with given parameters
///
/// Contrary to [gen_keys], this returns a [CrtClientKey]
///
/// ```rust
/// use tfhe::integer::gen_keys_crt;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // generate the client key and the server key:
/// let basis = vec![2, 3, 5];
/// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);
/// ```
pub fn gen_keys_crt(
    parameters_set: crate::shortint::parameters::ClassicPBSParameters,
    basis: Vec<u64>,
) -> (CrtClientKey, ServerKey) {
    let (cks, sks) = gen_keys(parameters_set);

    (CrtClientKey::from((cks, basis)), sks)
}
