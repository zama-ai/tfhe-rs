use super::{CrtCiphertext, RadixCiphertext, SignedRadixCiphertext};
use crate::shortint::Ciphertext;

pub trait IntegerCiphertext: Clone {
    fn blocks(&self) -> &[Ciphertext];
    fn moduli(&self) -> Vec<u64> {
        self.blocks().iter().map(|x| x.message_modulus.0).collect()
    }

    fn from_blocks(blocks: Vec<Ciphertext>) -> Self;

    fn blocks_mut(&mut self) -> &mut [Ciphertext];
}

pub trait IntegerRadixCiphertext: IntegerCiphertext + Sync + Send + From<Vec<Ciphertext>> {
    const IS_SIGNED: bool;

    fn block_carries_are_empty(&self) -> bool {
        self.blocks().iter().all(Ciphertext::carry_is_empty)
    }

    /// Returns whether the ciphertext _seems_ like it holds/encrypts
    /// a boolean (0 or 1) value.
    ///
    /// Since it uses degree to do so, it will not
    /// always return the correct answer.
    fn holds_boolean_value(&self) -> bool {
        self.blocks()[0].degree.get() <= 1
            && self.blocks()[1..]
                .iter()
                .all(|block| block.degree.get() == 0)
    }

    fn into_blocks(self) -> Vec<Ciphertext>;
}

impl IntegerCiphertext for RadixCiphertext {
    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
    }

    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        Self::from(blocks)
    }

    fn blocks_mut(&mut self) -> &mut [Ciphertext] {
        &mut self.blocks
    }
}

impl IntegerRadixCiphertext for RadixCiphertext {
    const IS_SIGNED: bool = false;

    fn into_blocks(self) -> Vec<Ciphertext> {
        self.blocks
    }
}

impl IntegerCiphertext for SignedRadixCiphertext {
    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
    }

    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        Self::from(blocks)
    }

    fn blocks_mut(&mut self) -> &mut [Ciphertext] {
        &mut self.blocks
    }
}

impl IntegerRadixCiphertext for SignedRadixCiphertext {
    const IS_SIGNED: bool = true;

    fn into_blocks(self) -> Vec<Ciphertext> {
        self.blocks
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

// Yet another trait, this is to avoid breaking the logic with IntegerCiphertext which BooleanBlock
// does not implement for good reasons IIRC.
pub trait AsShortintCiphertextSlice {
    fn as_ciphertext_slice(&self) -> &[Ciphertext];
}

impl<T: IntegerCiphertext> AsShortintCiphertextSlice for T {
    fn as_ciphertext_slice(&self) -> &[Ciphertext] {
        self.blocks()
    }
}

impl AsShortintCiphertextSlice for super::BooleanBlock {
    fn as_ciphertext_slice(&self) -> &[Ciphertext] {
        core::slice::from_ref(&self.0)
    }
}
