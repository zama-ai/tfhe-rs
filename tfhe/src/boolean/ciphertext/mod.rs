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

impl CompressedCiphertext {
    pub fn decompress(&self) -> Ciphertext {
        Ciphertext::Encrypted(self.ciphertext.decompress_into_lwe_ciphertext())
    }

    /// Deconstruct a [`CompressedCiphertext`] into its constituents.
    pub fn into_raw_parts(self) -> SeededLweCiphertext<u32> {
        self.ciphertext
    }

    /// Construct a [`CompressedCiphertext`] from its constituents.
    pub fn from_raw_parts(ciphertext: SeededLweCiphertext<u32>) -> Self {
        Self { ciphertext }
    }
}
