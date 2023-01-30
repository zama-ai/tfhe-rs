//! An encryption of a boolean message.
//!
//! This module implements the ciphertext structure containing an encryption of a Boolean message.

use crate::core_crypto::entities::*;
use serde::{Deserialize, Serialize};

/// A structure containing a ciphertext, meant to encrypt a Boolean message.
///
/// It is used to evaluate a Boolean circuits homomorphically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    Encrypted(LweCiphertextOwned<u32>),
    Trivial(bool),
}

/// A structure containing a compressed ciphertext, meant to encrypt a Boolean message.
///
/// It has to be decompressed before evaluating a Boolean circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub(crate) ciphertext: SeededLweCiphertext<u32>,
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        Self::Encrypted(value.ciphertext.decompress_into_lwe_ciphertext())
    }
}
