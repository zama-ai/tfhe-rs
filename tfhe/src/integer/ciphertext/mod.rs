//! This module implements the ciphertext structures.
pub mod boolean_value;

use super::parameters::{
    RadixCiphertextConformanceParams, RadixCompactCiphertextListConformanceParams,
};
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::block_decomposition::{BlockRecomposer, RecomposableFrom};
use crate::integer::client_key::{sign_extend_partial_number, RecomposableSignedInteger};
use crate::shortint::ciphertext::NotTrivialCiphertextError;
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

impl ParameterSetConformant for RadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.blocks.len() == params.num_blocks_per_integer
            && self
                .blocks
                .iter()
                .all(|block| block.is_conformant(&params.shortint_params))
    }
}

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

#[derive(Clone, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub(crate) ct_list: crate::shortint::ciphertext::CompactCiphertextList,
    // Keep track of the num_blocks, as we allow
    // storing many integer that have the same num_blocks
    // into ct_list
    pub(crate) num_blocks_per_integer: usize,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = RadixCompactCiphertextListConformanceParams;

    fn is_conformant(&self, params: &RadixCompactCiphertextListConformanceParams) -> bool {
        self.num_blocks_per_integer == params.num_blocks_per_integer
            && self
                .ct_list
                .is_conformant(&params.to_shortint_ct_list_conformance_parameters())
    }
}

impl CompactCiphertextList {
    pub fn expand_one<T: IntegerRadixCiphertext>(&self) -> T {
        let mut blocks = self.ct_list.expand();
        blocks.truncate(self.num_blocks_per_integer);
        T::from(blocks)
    }

    pub fn ciphertext_count(&self) -> usize {
        self.ct_list.ct_list.lwe_ciphertext_count().0 / self.num_blocks_per_integer
    }

    pub fn expand<T: IntegerRadixCiphertext>(&self) -> Vec<T> {
        let mut all_block_iter = self.ct_list.expand().into_iter();
        let num_ct = self.ciphertext_count();
        let mut ciphertexts = Vec::with_capacity(num_ct);

        for _ in 0..num_ct {
            let ct_blocks = all_block_iter
                .by_ref()
                .take(self.num_blocks_per_integer)
                .collect::<Vec<_>>();
            if ct_blocks.len() < self.num_blocks_per_integer {
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
        self.blocks.iter().all(Ciphertext::carry_is_empty)
    }

    pub fn is_trivial(&self) -> bool {
        self.blocks.iter().all(Ciphertext::is_trivial)
    }

    /// Decrypts a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // 8 bits
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
    ///
    /// let msg = 124u8;
    /// let msg2 = 17u8;
    ///
    /// // Trivial encryption
    /// let trivial_ct: RadixCiphertext = sks.create_trivial_radix(msg, 4);
    /// let non_trivial_ct = cks.encrypt(msg2);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// assert_eq!(Ok(msg), res);
    ///
    /// let res = non_trivial_ct.decrypt_trivial::<u8>();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial::<u8>();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations using only trivial ciphertexts
    /// // will return a trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &trivial_ct);
    /// let res = ct_res.decrypt_trivial::<u8>();
    /// assert_eq!(Ok(msg + msg), res);
    /// ```
    pub fn decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: UnsignedNumeric + RecomposableFrom<u64>,
    {
        let bits_in_block = self.blocks[0].message_modulus.0.ilog2();
        let mut recomposer = BlockRecomposer::<Clear>::new(bits_in_block);

        for encrypted_block in &self.blocks {
            let decrypted_block = encrypted_block.decrypt_trivial_message_and_carry()?;
            recomposer.add_unmasked(decrypted_block);
        }

        Ok(recomposer.value())
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

impl ParameterSetConformant for SignedRadixCiphertext {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.blocks.len() == params.num_blocks_per_integer
            && self
                .blocks
                .iter()
                .all(|block| block.is_conformant(&params.shortint_params))
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

impl SignedRadixCiphertext {
    pub fn block_carries_are_empty(&self) -> bool {
        self.blocks.iter().all(Ciphertext::carry_is_empty)
    }

    pub fn is_trivial(&self) -> bool {
        self.blocks.iter().all(Ciphertext::is_trivial)
    }

    /// Decrypts a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext, SignedRadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // 8 bits
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
    ///
    /// let msg = -35i8;
    /// let msg2 = 17i8;
    ///
    /// // Trivial encryption
    /// let trivial_ct: SignedRadixCiphertext = sks.create_trivial_radix(msg, 4);
    /// let non_trivial_ct = cks.encrypt_signed(msg2);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// assert_eq!(Ok(msg), res);
    ///
    /// let res = non_trivial_ct.decrypt_trivial::<i8>();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial::<i8>();
    /// matches!(res, Err(_));
    ///
    /// // Doing operations using only trivial ciphertexts
    /// // will return a trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &trivial_ct);
    /// let res = ct_res.decrypt_trivial::<i8>();
    /// assert_eq!(Ok(msg + msg), res);
    /// ```
    pub fn decrypt_trivial<Clear>(&self) -> Result<Clear, NotTrivialCiphertextError>
    where
        Clear: RecomposableSignedInteger,
    {
        let bits_in_block = self.blocks[0].message_modulus.0.ilog2();
        let mut recomposer = BlockRecomposer::<Clear>::new(bits_in_block);

        for encrypted_block in &self.blocks {
            let decrypted_block = encrypted_block.decrypt_trivial_message_and_carry()?;
            recomposer.add_unmasked(decrypted_block);
        }

        let num_bits_in_ctxt = bits_in_block * self.blocks.len() as u32;
        let unpadded_value = recomposer.value();
        Ok(sign_extend_partial_number(unpadded_value, num_bits_in_ctxt))
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
    fn blocks(&self) -> &[Ciphertext];
    fn moduli(&self) -> Vec<u64> {
        self.blocks()
            .iter()
            .map(|x| x.message_modulus.0 as u64)
            .collect()
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
        let moduli = blocks.iter().map(|x| x.message_modulus.0 as u64).collect();
        Self { blocks, moduli }
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
