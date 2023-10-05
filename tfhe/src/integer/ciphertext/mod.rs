//! This module implements the ciphertext structures.
use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::{Ciphertext, CompressedCiphertext};
use serde::{Deserialize, Serialize};

/// Structure containing a ciphertext in radix decomposition
/// holding an unsigned value.
#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug)]
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
pub type RadixCiphertext = BaseRadixCiphertext<Ciphertext>;

/// Structure containing a **compressed** ciphertext in radix decomposition.
pub type CompressedRadixCiphertext = BaseRadixCiphertext<CompressedCiphertext>;

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

#[derive(Clone, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Keep track of the num_blocks, as we allow
    // storing many integer that have the same num_blocks
    // into ct_list
    pub(crate) num_blocks: usize,
}

/// Structure to store the expected properties of a ciphertext list
/// Can be used on a server to check if client inputs are well formed
/// before running a computation on them
pub struct CiphertextListConformanceParams {
    pub shortint_params: CiphertextConformanceParams,
    pub num_blocks_per_integer: usize,
    pub num_integers_constraint: ListSizeConstraint,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CiphertextListConformanceParams;

    fn is_conformant(&self, params: &CiphertextListConformanceParams) -> bool {
        let CiphertextListConformanceParams {
            shortint_params,
            num_blocks_per_integer,
            num_integers_constraint,
        } = params;

        let num_blocks_constraint =
            num_integers_constraint.multiply_group_size(*num_blocks_per_integer);

        self.num_blocks == *num_blocks_per_integer
            && self.ct_list.is_conformant(
                &shortint_params.to_ct_list_conformance_parameters(num_blocks_constraint),
            )
    }
}

impl CompactCiphertextList {
    pub fn expand_one<T: IntegerRadixCiphertext>(&self) -> T {
        let mut blocks = self.ct_list.expand();
        blocks.truncate(self.num_blocks);
        T::from(blocks)
    }

    pub fn ciphertext_count(&self) -> usize {
        self.ct_list.ct_list.lwe_ciphertext_count().0 / self.num_blocks
    }

    pub fn expand<T: IntegerRadixCiphertext>(&self) -> Vec<T> {
        let mut all_block_iter = self.ct_list.expand().into_iter();
        let num_ct = self.ciphertext_count();
        let mut ciphertexts = Vec::with_capacity(num_ct);

        for _ in 0..num_ct {
            let ct_blocks = all_block_iter
                .by_ref()
                .take(self.num_blocks)
                .collect::<Vec<_>>();
            if ct_blocks.len() < self.num_blocks {
                break;
            }
            let ct = T::from(ct_blocks);
            ciphertexts.push(ct);
        }

        ciphertexts
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }
}

impl RadixCiphertext {
    pub fn block_carries_are_empty(&self) -> bool {
        self.blocks.iter().all(|block| block.carry_is_empty())
    }
}

/// Structure containing a ciphertext in radix decomposition
/// holding a signed value.
#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug)]
pub struct BaseSignedRadixCiphertext<Block> {
    /// The blocks are stored from LSB to MSB
    pub(crate) blocks: Vec<Block>,
}

impl<Block> From<Vec<Block>> for BaseSignedRadixCiphertext<Block> {
    fn from(blocks: Vec<Block>) -> Self {
        Self { blocks }
    }
}

// Type alias to save some typing in implementation parts
pub type SignedRadixCiphertext = BaseSignedRadixCiphertext<Ciphertext>;

/// Structure containing a **compressed** ciphertext in radix decomposition
/// holding a signed valued
pub type CompressedSignedRadixCiphertext = BaseSignedRadixCiphertext<CompressedCiphertext>;

impl SignedRadixCiphertext {
    pub fn block_carries_are_empty(&self) -> bool {
        self.blocks.iter().all(|block| block.carry_is_empty())
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

pub trait IntegerCiphertext: Clone {
    fn from_blocks(blocks: Vec<Ciphertext>) -> Self;
    fn blocks(&self) -> &[Ciphertext];
    fn blocks_mut(&mut self) -> &mut [Ciphertext];
    fn moduli(&self) -> Vec<u64> {
        self.blocks()
            .iter()
            .map(|x| x.message_modulus.0 as u64)
            .collect()
    }
}

pub trait IntegerRadixCiphertext: IntegerCiphertext + Sync + Send + From<Vec<Ciphertext>> {
    const IS_SIGNED: bool;

    fn block_carries_are_empty(&self) -> bool {
        self.blocks().iter().all(|block| block.carry_is_empty())
    }

    /// Returns whether the ciphertext _seems_ like it holds/encrypts
    /// a boolean (0 or 1) value.
    ///
    /// Since it uses degree to do so, it will not
    /// always return the correct answer.
    fn holds_boolean_value(&self) -> bool {
        self.blocks()[0].degree.0 <= 1 && self.blocks()[1..].iter().all(|block| block.degree.0 == 0)
    }

    fn into_blocks(self) -> Vec<Ciphertext>;
}

impl IntegerCiphertext for RadixCiphertext {
    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        Self::from(blocks)
    }

    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
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
    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        Self::from(blocks)
    }
    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
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
    fn from_blocks(blocks: Vec<Ciphertext>) -> Self {
        let moduli = blocks.iter().map(|x| x.message_modulus.0 as u64).collect();
        Self { blocks, moduli }
    }
    fn blocks(&self) -> &[Ciphertext] {
        &self.blocks
    }
    fn blocks_mut(&mut self) -> &mut [Ciphertext] {
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
pub type CrtCiphertext = BaseCrtCiphertext<Ciphertext>;

/// Structure containing a **compressed** ciphertext in CRT decomposition.
pub type CompressedCrtCiphertext = BaseCrtCiphertext<CompressedCiphertext>;

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
