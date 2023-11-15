//! This module implements the ciphertext structure containing an encryption of an integer message.
use serde::{Deserialize, Serialize};
use tfhe::shortint;

/// Id to recognize the key used to encrypt a block.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct KeyId(pub usize);

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub ct_vec_mantissa: Vec<shortint::ciphertext::Ciphertext>,
    pub ct_vec_exponent: Vec<shortint::ciphertext::Ciphertext>,
    pub ct_sign: shortint::ciphertext::Ciphertext,
    pub(crate) e_min: i64,
}
impl Ciphertext {
    /// Returns the slice of blocks that the ciphertext is composed of.
    pub fn mantissa_blocks(&self) -> &[shortint::Ciphertext] {
        &self.ct_vec_mantissa
    }
    pub fn exponent_blocks(&self) -> &[shortint::Ciphertext] {
        &self.ct_vec_exponent
    }
    pub fn sign(&self) -> &shortint::Ciphertext {
        &self.ct_sign
    }
    pub fn e_min(&self) -> &i64 {
        &self.e_min
    }
}
