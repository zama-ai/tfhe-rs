use super::super::parameters::RadixCiphertextConformanceParams;
use super::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CrtCiphertext,
    RadixCiphertext, SignedRadixCiphertext,
};
use crate::conformance::ParameterSetConformant;
use crate::shortint::CompressedCiphertext;

/// Structure containing a **compressed** ciphertext in radix decomposition.
pub type CompressedRadixCiphertext = BaseRadixCiphertext<CompressedCiphertext>;

impl ParameterSetConformant for CompressedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.blocks.len() == params.num_blocks_per_integer
            && self
                .blocks
                .iter()
                .all(|block| block.is_conformant(&params.shortint_params))
    }
}

impl CompressedRadixCiphertext {
    pub fn decompress(&self) -> RadixCiphertext {
        RadixCiphertext::from(
            self.blocks
                .iter()
                .map(CompressedCiphertext::decompress)
                .collect::<Vec<_>>(),
        )
    }
}

/// Structure containing a **compressed** ciphertext in radix decomposition
/// holding a signed valued
pub type CompressedSignedRadixCiphertext = BaseSignedRadixCiphertext<CompressedCiphertext>;

impl ParameterSetConformant for CompressedSignedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.blocks.len() == params.num_blocks_per_integer
            && self
                .blocks
                .iter()
                .all(|block| block.is_conformant(&params.shortint_params))
    }
}

impl CompressedSignedRadixCiphertext {
    pub fn decompress(&self) -> SignedRadixCiphertext {
        SignedRadixCiphertext::from(
            self.blocks
                .iter()
                .map(CompressedCiphertext::decompress)
                .collect::<Vec<_>>(),
        )
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
