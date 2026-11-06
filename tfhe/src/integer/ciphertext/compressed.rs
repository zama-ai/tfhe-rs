use super::{
    BaseCrtCiphertext, BaseRadixCiphertext, BaseSignedRadixCiphertext, CrtCiphertext,
    RadixCiphertext, SignedRadixCiphertext,
};
use crate::shortint::CompressedCiphertext;

/// Structure containing a **compressed** ciphertext in radix decomposition.
pub type CompressedRadixCiphertext = BaseRadixCiphertext<CompressedCiphertext>;

impl CompressedRadixCiphertext {
    pub fn decompress(&self) -> RadixCiphertext {
        let Self { blocks } = self;

        RadixCiphertext::from(
            blocks
                .iter()
                .map(CompressedCiphertext::decompress)
                .collect::<Vec<_>>(),
        )
    }
}

/// Structure containing a **compressed** ciphertext in radix decomposition
/// holding a signed valued
pub type CompressedSignedRadixCiphertext = BaseSignedRadixCiphertext<CompressedCiphertext>;

impl CompressedSignedRadixCiphertext {
    pub fn decompress(&self) -> SignedRadixCiphertext {
        let Self { blocks } = self;

        SignedRadixCiphertext::from(
            blocks
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
        let Self { blocks, moduli } = self;

        let blocks = blocks
            .iter()
            .map(CompressedCiphertext::decompress)
            .collect::<Vec<_>>();
        CrtCiphertext::from((blocks, moduli.clone()))
    }
}
