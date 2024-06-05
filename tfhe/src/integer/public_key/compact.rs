use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CompactCiphertextList, RadixCiphertext};
use crate::integer::encryption::encrypt_words_radix_impl;
use crate::integer::{ClientKey, SignedRadixCiphertext};
use crate::shortint::{
    CompactPublicKey as ShortintCompactPublicKey,
    CompressedCompactPublicKey as ShortintCompressedCompactPublicKey,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactPublicKey {
    pub(crate) key: ShortintCompactPublicKey,
}

impl CompactPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let key = ShortintCompactPublicKey::new(&client_key.key);
        Self { key }
    }

    pub fn try_new(client_key: &ClientKey) -> Option<Self> {
        let key = ShortintCompactPublicKey::try_new(&client_key.key)?;
        Some(Self { key })
    }

    /// Deconstruct a [`CompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> ShortintCompactPublicKey {
        self.key
    }

    /// Construct a [`CompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: ShortintCompactPublicKey) -> Self {
        Self { key }
    }

    pub fn encrypt_radix<T>(&self, message: T, num_blocks: usize) -> RadixCiphertext
    where
        T: DecomposableInto<u64> + UnsignedNumeric,
    {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            ShortintCompactPublicKey::encrypt,
        )
    }

    pub fn encrypt_signed_radix<T>(&self, message: T, num_blocks: usize) -> SignedRadixCiphertext
    where
        T: DecomposableInto<u64> + SignedNumeric,
    {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            ShortintCompactPublicKey::encrypt,
        )
    }

    pub fn encrypt_radix_compact<T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>>(
        &self,
        message: T,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        CompactCiphertextList::builder(self)
            .push_with_num_blocks(message, num_blocks_per_integer)
            .build()
    }

    pub fn encrypt_slice_radix_compact<
        T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
    >(
        &self,
        messages: &[T],
        num_blocks: usize,
    ) -> CompactCiphertextList {
        self.encrypt_iter_radix_compact(messages.iter().copied(), num_blocks)
    }

    pub fn encrypt_iter_radix_compact<
        T: DecomposableInto<u64> + std::ops::Shl<usize, Output = T>,
    >(
        &self,
        message_iter: impl Iterator<Item = T>,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        let mut builder = CompactCiphertextList::builder(self);
        builder.extend_with_num_blocks(message_iter, num_blocks_per_integer);
        builder.build()
    }

    pub fn size_elements(&self) -> usize {
        self.key.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.key.size_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedCompactPublicKey {
    pub(crate) key: ShortintCompressedCompactPublicKey,
}

impl CompressedCompactPublicKey {
    pub fn new(client_key: &ClientKey) -> Self {
        let key = ShortintCompressedCompactPublicKey::new(&client_key.key);
        Self { key }
    }

    /// Deconstruct a [`CompressedCompactPublicKey`] into its constituents.
    pub fn into_raw_parts(self) -> ShortintCompressedCompactPublicKey {
        self.key
    }

    /// Construct a [`CompressedCompactPublicKey`] from its constituents.
    pub fn from_raw_parts(key: ShortintCompressedCompactPublicKey) -> Self {
        Self { key }
    }

    pub fn decompress(&self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
        }
    }
}
