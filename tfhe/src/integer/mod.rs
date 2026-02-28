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
//! use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
//!
//! //4 blocks for the radix decomposition
//! let number_of_blocks = 4;
//! // Modulus = (2^2)*4 = 2^8 (from the parameters chosen and the number of blocks
//! let modulus = 1u64 << 8;
//!
//! // Generation of the client/server keys, using the default parameters:
//! let (client_key, server_key) = gen_keys_radix(
//!     PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
//!     number_of_blocks,
//! );
//!
//! let msg1 = 153u64;
//! let msg2 = 125u64;
//!
//! // Encryption of two messages using the client key:
//! let ct_1 = client_key.encrypt(msg1);
//! let ct_2 = client_key.encrypt(msg2);
//!
//! // Homomorphic evaluation of an integer circuit (here, an addition) using the server key:
//! let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);
//!
//! // Decryption of the ciphertext using the client key:
//! let output: u64 = client_key.decrypt(&ct_3);
//! assert_eq!(output, (msg1 + msg2) % modulus);
//! ```
//!
//! # Warning
//! This uses cryptographic parameters from the [`shortint`](`crate::shortint`) module.
//! Currently, the radix approach is only compatible with parameter sets such
//! that the message and carry buffers have the same size.

pub mod block_decomposition;
pub(crate) mod encryption;
#[cfg(test)]
mod tests;

pub mod backward_compatibility;
pub mod bigint;
pub mod ciphertext;
pub mod client_key;
pub mod compression_keys;
pub mod key_switching_key;
#[cfg(any(test, feature = "internal-keycache"))]
pub mod keycache;
pub mod noise_squashing;
pub mod oprf;
pub mod parameters;
pub mod prelude;
pub mod public_key;
pub mod server_key;

#[cfg(feature = "gpu")]
pub mod gpu;

#[cfg(feature = "hpu")]
pub mod hpu;

#[cfg(feature = "zk-pok")]
pub use ciphertext::ProvenCompactCiphertextList;

pub use bigint::i256::I256;
pub use bigint::i512::I512;
pub use bigint::u256::U256;
pub use bigint::u512::U512;
pub use ciphertext::boolean_value::BooleanBlock;
pub use ciphertext::{
    CrtCiphertext, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext,
    SignedRadixCiphertext,
};
pub use client_key::{ClientKey, CrtClientKey, RadixClientKey};
pub use public_key::{
    CompactPrivateKey, CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey,
};
pub use server_key::{CheckError, CompressedServerKey, ServerKey};

/// Enum to indicate which kind of computations the [`ServerKey`] will be performing, this changes
/// the parameterization of the key to manage carries in the Radix case.
#[derive(Clone, Copy, Debug)]
pub enum IntegerKeyKind {
    Radix,
    CRT,
}

/// Unless you know what you are doing you are likely looking for [`gen_keys_radix`] or
/// [`gen_keys_crt`].
///
/// Generate a couple of client and server keys with given parameters
///
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is meant to
///   be published (the client sends it to the server).
pub(crate) fn gen_keys<P>(parameters_set: P, key_kind: IntegerKeyKind) -> (ClientKey, ServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let shortint_parameters_set: crate::shortint::parameters::ShortintParameterSet =
        parameters_set.try_into().unwrap();

    #[cfg(any(test, feature = "internal-keycache"))]
    {
        keycache::KEY_CACHE.get_from_params(shortint_parameters_set.ap_parameters(), key_kind)
    }
    #[cfg(all(not(test), not(feature = "internal-keycache")))]
    {
        let cks = ClientKey::new(shortint_parameters_set);
        let sks = match key_kind {
            IntegerKeyKind::Radix => ServerKey::new_radix_server_key(&cks),
            IntegerKeyKind::CRT => ServerKey::new_crt_server_key(&cks),
        };

        (cks, sks)
    }
}

/// Generate a couple of client and server keys with given parameters.
///
/// Note: the resulting [`ServerKey`] can be fairly large, if needed you can generate a
/// [`CompressedServerKey`] instead to reduce storage and network bandwidth usage.
///
/// ```rust
/// use tfhe::integer::gen_keys_radix;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
///
/// // generate the client key and the server key:
/// let num_blocks = 4;
/// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
/// ```
pub fn gen_keys_radix<P>(parameters_set: P, num_blocks: usize) -> (RadixClientKey, ServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let (cks, sks) = gen_keys(parameters_set, IntegerKeyKind::Radix);

    (RadixClientKey::from((cks, num_blocks)), sks)
}

/// Generate a couple of client and server keys with given parameters.
///
/// Note: the resulting [`ServerKey`] can be fairly large, if needed you can generate a
/// [`CompressedServerKey`] instead to reduce storage and network bandwidth usage.
///
/// ```rust
/// use tfhe::integer::gen_keys_crt;
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
///
/// // generate the client key and the server key:
/// let basis = vec![2, 3, 5];
/// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, basis);
/// ```
pub fn gen_keys_crt<P>(parameters_set: P, basis: Vec<u64>) -> (CrtClientKey, ServerKey)
where
    P: TryInto<crate::shortint::parameters::ShortintParameterSet>,
    <P as TryInto<crate::shortint::parameters::ShortintParameterSet>>::Error: std::fmt::Debug,
{
    let (cks, sks) = gen_keys(parameters_set, IntegerKeyKind::CRT);

    (CrtClientKey::from((cks, basis)), sks)
}
