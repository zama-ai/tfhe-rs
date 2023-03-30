//! This module implements the ciphertext structures.
use crate::shortint::ciphertext::{BootstrapKeyswitch, KeyswitchBootstrap};
use crate::shortint::{
    CiphertextBase, CiphertextBig, CiphertextSmall, CompressedCiphertextBig,
    CompressedCiphertextSmall, PBSOrderMarker,
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

// Type alias to save some typing in implementation parts
pub type RadixCiphertext<PBSOder> = BaseRadixCiphertext<CiphertextBase<PBSOder>>;

/// Structure containing a ciphertext in radix decomposition.
pub type RadixCiphertextBig = BaseRadixCiphertext<CiphertextBig>;
pub type RadixCiphertextSmall = BaseRadixCiphertext<CiphertextSmall>;

/// Structure containing a **compressed** ciphertext in radix decomposition.
pub type CompressedRadixCiphertextBig = BaseRadixCiphertext<CompressedCiphertextBig>;
pub type CompressedRadixCiphertextSmall = BaseRadixCiphertext<CompressedCiphertextSmall>;

impl From<CompressedRadixCiphertextBig> for RadixCiphertextBig {
    fn from(compressed: CompressedRadixCiphertextBig) -> Self {
        Self::from(
            compressed
                .blocks
                .into_iter()
                .map(From::from)
                .collect::<Vec<_>>(),
        )
    }
}

impl From<CompressedRadixCiphertextSmall> for RadixCiphertextSmall {
    fn from(compressed: CompressedRadixCiphertextSmall) -> Self {
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
    type PBSOrder: PBSOrderMarker;

    fn from_blocks(blocks: Vec<CiphertextBase<Self::PBSOrder>>) -> Self;
    fn blocks(&self) -> &[CiphertextBase<Self::PBSOrder>];
    fn blocks_mut(&mut self) -> &mut [CiphertextBase<Self::PBSOrder>];
    fn moduli(&self) -> Vec<u64> {
        self.blocks()
            .iter()
            .map(|x| x.message_modulus.0 as u64)
            .collect()
    }
}

impl IntegerCiphertext for RadixCiphertextBig {
    type PBSOrder = KeyswitchBootstrap;

    fn from_blocks(blocks: Vec<CiphertextBase<Self::PBSOrder>>) -> Self {
        Self::from(blocks)
    }
    fn blocks(&self) -> &[CiphertextBase<Self::PBSOrder>] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [CiphertextBase<Self::PBSOrder>] {
        &mut self.blocks
    }
}

impl IntegerCiphertext for RadixCiphertextSmall {
    type PBSOrder = BootstrapKeyswitch;

    fn from_blocks(blocks: Vec<CiphertextBase<Self::PBSOrder>>) -> Self {
        Self::from(blocks)
    }
    fn blocks(&self) -> &[CiphertextBase<Self::PBSOrder>] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [CiphertextBase<Self::PBSOrder>] {
        &mut self.blocks
    }
}

impl IntegerCiphertext for CrtCiphertext {
    type PBSOrder = KeyswitchBootstrap;

    fn from_blocks(blocks: Vec<CiphertextBase<Self::PBSOrder>>) -> Self {
        let moduli = blocks.iter().map(|x| x.message_modulus.0 as u64).collect();
        Self { blocks, moduli }
    }
    fn blocks(&self) -> &[CiphertextBase<Self::PBSOrder>] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [CiphertextBase<Self::PBSOrder>] {
        &mut self.blocks
    }

    fn moduli(&self) -> Vec<u64> {
        self.moduli.clone()
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
pub type CrtCiphertext = BaseCrtCiphertext<CiphertextBig>;

/// Structure containing a **compressed** ciphertext in CRT decomposition.
pub type CompressedCrtCiphertext = BaseCrtCiphertext<CompressedCiphertextBig>;

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
