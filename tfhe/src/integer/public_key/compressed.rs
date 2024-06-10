use tfhe_versionable::Versionize;

use crate::integer::backward_compatibility::public_key::CompressedPublicKeyVersions;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CrtCiphertext, RadixCiphertext};
use crate::integer::client_key::ClientKey;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl};
use crate::integer::{BooleanBlock, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::MessageModulus;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(CompressedPublicKeyVersions)]
pub struct CompressedPublicKey {
    pub(crate) key: crate::shortint::CompressedPublicKey,
}

impl CompressedPublicKey {
    pub fn new<C>(client_key: &C) -> Self
    where
        C: AsRef<ClientKey>,
    {
        Self {
            key: crate::shortint::CompressedPublicKey::new(&client_key.as_ref().key),
        }
    }

    /// Deconstruct a [`CompressedPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> crate::shortint::CompressedPublicKey {
        self.key
    }

    /// Construct a [`CompressedPublicKey`] from its constituents.
    pub fn from_raw_parts(key: crate::shortint::CompressedPublicKey) -> Self {
        Self { key }
    }

    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::CompressedPublicKey::encrypt_with_message_modulus,
        )
    }

    pub fn encrypt_native_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt(msg, moduli.0 as u8)
        })
    }

    fn encrypt_crt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        base_vec: Vec<u64>,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::CompressedPublicKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }

    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    pub fn encrypt_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKey::encrypt,
        )
    }

    pub fn encrypt_signed_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> SignedRadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKey::encrypt,
        )
    }

    pub fn encrypt_bool(&self, message: bool) -> BooleanBlock {
        let mut ciphertext = self.key.encrypt(u64::from(message));
        ciphertext.degree = Degree::new(1);
        BooleanBlock::new_unchecked(ciphertext)
    }

    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::CompressedPublicKey::encrypt_without_padding,
        )
    }

    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: DecomposableInto<u64>,
        F: Fn(&crate::shortint::CompressedPublicKey, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_words_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }
}
