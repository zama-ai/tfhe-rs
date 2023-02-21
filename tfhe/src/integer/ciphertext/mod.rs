//! This module implements the ciphertext structures.
use crate::shortint::{
    CiphertextBig as ShortintCiphertext, CompressedCiphertextBig as CompressedShortintCiphertext,
};
use serde::{Deserialize, Serialize};

/// Structure containing a ciphertext in radix decomposition.
#[derive(Serialize, Clone, Deserialize)]
pub struct BaseRadixCiphertext<Block> {
    /// The blocks are stored from LSB to MSB
    pub(crate) blocks: Vec<Block>,
}

impl<Block> From<Vec<Block>> for BaseRadixCiphertext<Block> {
    fn from(blocks: Vec<Block>) -> Self {
        Self { blocks }
    }
}
/// Structure containing a ciphertext in radix decomposition.
pub type RadixCiphertext = BaseRadixCiphertext<ShortintCiphertext>;

/// Structure containing a **compressed** ciphertext in radix decomposition.
pub type CompressedRadixCiphertext = BaseRadixCiphertext<CompressedShortintCiphertext>;

impl From<CompressedRadixCiphertext> for RadixCiphertext {
    fn from(compressed: CompressedRadixCiphertext) -> Self {
        Self::from(
            compressed
                .blocks
                .into_iter()
                .map(From::from)
                .collect::<Vec<_>>(),
        )
    }
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
pub struct BaseCrtCiphertext<Block> {
    pub(crate) blocks: Vec<Block>,
    pub(crate) moduli: Vec<u64>,
}

/// Structure containing a ciphertext in CRT decomposition.
pub type CrtCiphertext = BaseCrtCiphertext<ShortintCiphertext>;

/// Structure containing a **compressed** ciphertext in CRT decomposition.
pub type CompressedCrtCiphertext = BaseCrtCiphertext<CompressedShortintCiphertext>;

impl<Block> From<(Vec<Block>, Vec<u64>)> for BaseCrtCiphertext<Block> {
    fn from((blocks, moduli): (Vec<Block>, Vec<u64>)) -> Self {
        Self { blocks, moduli }
    }
}

impl From<CompressedCrtCiphertext> for CrtCiphertext {
    fn from(compressed: CompressedCrtCiphertext) -> Self {
        let blocks = compressed
            .blocks
            .into_iter()
            .map(From::from)
            .collect::<Vec<_>>();
        let moduli = compressed.moduli;
        Self::from((blocks, moduli))
    }
}
