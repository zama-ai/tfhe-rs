//! This module implements the ciphertext structure containing an encryption of an integer message.
use crate::shortint::ciphertext::Ciphertext as ShortintCiphertext;
use serde::{Deserialize, Serialize};

/// Id to recognize the key used to encrypt a block.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct KeyId(pub usize);

#[derive(Serialize, Clone, Deserialize)]
pub struct Ciphertext {
    pub(crate) ct_vec_float: Vec<ShortintCiphertext>,
    pub(crate) nb_bit_mantissa: usize,
    pub(crate) nb_bit_exponent: usize,
    pub(crate) e_min: i64,

    pub(crate) key_id_vec: Vec<KeyId>,
}

impl Ciphertext {
    /// Returns the slice of blocks that the ciphertext is composed of.
    pub fn ct_vec_float(&self) -> &[ShortintCiphertext] {
        &self.ct_vec_float
    }
    pub fn nb_bit_mantissa(&self) -> &usize {
        &self.nb_bit_mantissa
    }
    pub fn nb_bit_exponent(&self) -> &usize {
        &self.nb_bit_exponent
    }
    pub fn e_min(&self) -> &i64 {
        &self.e_min
    }
}
