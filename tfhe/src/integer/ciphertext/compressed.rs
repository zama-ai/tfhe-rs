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

impl From<CompressedSignedRadixCiphertext> for SignedRadixCiphertext {
    fn from(compressed: CompressedSignedRadixCiphertext) -> Self {
        Self::from(
            compressed
                .blocks
                .into_iter()
                .map(From::from)
                .collect::<Vec<_>>(),
        )
    }
}

/// Structure containing a **compressed** ciphertext in CRT decomposition.
pub type CompressedCrtCiphertext = BaseCrtCiphertext<CompressedCiphertext>;

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
