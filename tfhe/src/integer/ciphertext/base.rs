use super::super::parameters::RadixCiphertextConformanceParams;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::backward_compatibility::ciphertext::{
    BaseCrtCiphertextVersions, BaseRadixCiphertextVersions, BaseSignedRadixCiphertextVersions,
};
use crate::integer::block_decomposition::{
    BlockRecomposer, RecomposableFrom, RecomposableSignedInteger,
};
use crate::integer::ciphertext::{re_randomize_ciphertext_blocks, ReRandomizationSeed};
use crate::integer::key_switching_key::KeySwitchingKeyMaterialView;
use crate::integer::CompactPublicKey;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::parameters::CiphertextConformanceParams;
use crate::shortint::Ciphertext;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Structure containing a ciphertext in radix decomposition
/// holding an unsigned value.
#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(BaseRadixCiphertextVersions)]
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

impl<T: ParameterSetConformant<ParameterSet = CiphertextConformanceParams>> ParameterSetConformant
    for BaseRadixCiphertext<T>
{
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        let Self { blocks } = self;

        blocks.len() == params.num_blocks_per_integer
            && blocks
                .iter()
                .all(|block| block.is_conformant(&params.shortint_params))
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // 8 bits
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, 4);
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
    /// assert!(res.is_err());
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial::<u8>();
    /// assert!(res.is_err());
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
        if !self.blocks.iter().all(|b| b.is_trivial()) {
            return Err(NotTrivialCiphertextError);
        }

        let bits_in_block = self.blocks[0].message_modulus.0.ilog2();

        let decrypted_block_iter = self
            .blocks
            .iter()
            .map(|block| block.decrypt_trivial_message_and_carry().unwrap());

        Ok(BlockRecomposer::recompose_unsigned(
            decrypted_block_iter,
            bits_in_block,
        ))
    }

    pub fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: Option<&KeySwitchingKeyMaterialView>,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        re_randomize_ciphertext_blocks(
            &mut self.blocks,
            compact_public_key,
            key_switching_key_material,
            seed,
        )?;

        Ok(())
    }
}

/// Structure containing a ciphertext in radix decomposition
/// holding a signed value.
#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(BaseSignedRadixCiphertextVersions)]
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

impl<T: ParameterSetConformant<ParameterSet = CiphertextConformanceParams>> ParameterSetConformant
    for BaseSignedRadixCiphertext<T>
{
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        let Self { blocks } = self;

        blocks.len() == params.num_blocks_per_integer
            && blocks
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
    /// use tfhe::integer::{gen_keys_radix, SignedRadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // 8 bits
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, 4);
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
    /// assert!(res.is_err());
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add_parallelized(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial::<i8>();
    /// assert!(res.is_err());
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
        if !self.blocks.iter().all(|b| b.is_trivial()) {
            return Err(NotTrivialCiphertextError);
        }

        let bits_in_block = self.blocks[0].message_modulus.0.ilog2();

        let decrypted_block_iter = self
            .blocks
            .iter()
            .map(|block| block.decrypt_trivial_message_and_carry().unwrap());

        Ok(BlockRecomposer::recompose_signed(
            decrypted_block_iter,
            bits_in_block,
        ))
    }

    pub fn re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: Option<&KeySwitchingKeyMaterialView>,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        re_randomize_ciphertext_blocks(
            &mut self.blocks,
            compact_public_key,
            key_switching_key_material,
            seed,
        )?;

        Ok(())
    }
}

/// Structure containing a ciphertext in CRT decomposition.
///
/// For this CRT decomposition, each block is encrypted using
/// the same parameters.
#[derive(Serialize, Clone, Deserialize, Versionize)]
#[versionize(BaseCrtCiphertextVersions)]
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
