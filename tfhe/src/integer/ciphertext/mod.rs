//! This module implements the ciphertext structures.
use crate::shortint::Ciphertext as ShortintCiphertext;
use serde::{Deserialize, Serialize};

/// Structure containing a ciphertext in radix decomposition.
#[derive(Serialize, Clone, Deserialize)]
pub struct RadixCiphertext {
    /// The blocks are stored from LSB to MSB
    pub blocks: Vec<ShortintCiphertext>,
}

pub trait IntegerCiphertext: Clone {
    fn from_blocks(blocks: Vec<ShortintCiphertext>) -> Self;
    fn blocks(&self) -> &[ShortintCiphertext];
    fn blocks_mut(&mut self) -> &mut [ShortintCiphertext];
    fn moduli(&self) -> Vec<u64> {
        self.blocks()
            .iter()
            .map(|x| x.message_modulus.0 as u64)
            .collect()
    }
}

impl IntegerCiphertext for RadixCiphertext {
    fn blocks(&self) -> &[ShortintCiphertext] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [ShortintCiphertext] {
        &mut self.blocks
    }
    fn from_blocks(blocks: Vec<ShortintCiphertext>) -> Self {
        Self { blocks }
    }
}

impl IntegerCiphertext for CrtCiphertext {
    fn blocks(&self) -> &[ShortintCiphertext] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [ShortintCiphertext] {
        &mut self.blocks
    }
    fn from_blocks(blocks: Vec<ShortintCiphertext>) -> Self {
        let moduli = blocks.iter().map(|x| x.message_modulus.0 as u64).collect();
        Self { blocks, moduli }
    }
}

/// Structure containing a ciphertext in CRT decomposition.
///
/// For this CRT decomposition, each block is encrypted using
/// the same parameters.
#[derive(Serialize, Clone, Deserialize)]
pub struct CrtCiphertext {
    pub blocks: Vec<ShortintCiphertext>,
    pub(crate) moduli: Vec<u64>,
}

pub fn crt_ciphertext_from_ciphertext(ct: &ShortintCiphertext) -> CrtCiphertext{
    CrtCiphertext {
        blocks: vec![ct.clone(); 1],
        moduli: vec![ct.message_modulus.0 as u64; 1],
    }
}