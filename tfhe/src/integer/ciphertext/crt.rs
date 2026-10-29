use super::IntegerCiphertext;
use crate::shortint::{Ciphertext, CompressedCiphertext};
use serde::{Deserialize, Serialize};

/// Structure containing a ciphertext in CRT decomposition.
///
/// For this CRT decomposition, each block is encrypted using
/// the same parameters.
// Experimental type, serializable but intentionally not versioned
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
#[derive(Serialize, Clone, Deserialize)]
pub struct BaseCrtCiphertext<Block> {
    pub(crate) blocks: Vec<Block>,
    pub(crate) moduli: Vec<u64>,
}

/// Structure containing a ciphertext in CRT decomposition.
pub type CrtCiphertext = BaseCrtCiphertext<Ciphertext>;

impl<Block> From<(Vec<Block>, Vec<u64>)> for BaseCrtCiphertext<Block> {
    fn from((blocks, moduli): (Vec<Block>, Vec<u64>)) -> Self {
        Self { blocks, moduli }
    }
}

/// Structure containing a **compressed** ciphertext in CRT decomposition.
pub type CompressedCrtCiphertext = BaseCrtCiphertext<CompressedCiphertext>;

impl CompressedCrtCiphertext {
    pub fn decompress(&self) -> CrtCiphertext {
        let blocks = self
            .blocks
            .iter()
            .map(CompressedCiphertext::decompress)
            .collect::<Vec<_>>();
        let moduli = self.moduli.clone();
        CrtCiphertext::from((blocks, moduli))
    }
}

impl IntegerCiphertext for CrtCiphertext {
    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
    }

    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        let moduli = blocks.iter().map(|x| x.message_modulus.0).collect();
        Self { blocks, moduli }
    }

    fn blocks_mut(&mut self) -> &mut [Ciphertext] {
        &mut self.blocks
    }

    fn moduli(&self) -> Vec<u64> {
        self.moduli.clone()
    }
}
