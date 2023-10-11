use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use serde::{Deserialize, Serialize};

use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CompactCiphertextList, RadixCiphertext};
use crate::integer::encryption::{create_clear_radix_block_iterator, encrypt_words_radix_impl};
use crate::integer::{ClientKey, SignedRadixCiphertext};
use crate::shortint::{
    CompactPublicKey as ShortintCompactPublicKey,
    CompressedCompactPublicKey as ShortintCompressedCompactPublicKey,
};

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

    pub fn encrypt_radix_compact<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        let clear_block_iter = create_clear_radix_block_iterator(
            message,
            self.key.parameters.message_modulus(),
            num_blocks_per_integer,
        );

        let ct_list = self.key.encrypt_iter(clear_block_iter);
        CompactCiphertextList {
            ct_list,
            num_blocks_per_integer,
        }
    }

    pub fn encrypt_slice_radix_compact<T: DecomposableInto<u64>>(
        &self,
        messages: &[T],
        num_blocks: usize,
    ) -> CompactCiphertextList {
        self.encrypt_iter_radix_compact(messages.iter().copied(), num_blocks)
    }

    pub fn encrypt_iter_radix_compact<T: DecomposableInto<u64>>(
        &self,
        mut message_iter: impl Iterator<Item = T>,
        num_blocks_per_integer: usize,
    ) -> CompactCiphertextList {
        let mut iterator_chain;
        match (message_iter.next(), message_iter.next()) {
            (None, None) => panic!("At least one message is required"),
            (None, Some(_)) => unreachable!(),
            (Some(first_message), None) => {
                // Cannot form a chain
                return self.encrypt_radix_compact(first_message, num_blocks_per_integer);
            }
            (Some(first_message), Some(second_message)) => {
                let first_iter = create_clear_radix_block_iterator(
                    first_message,
                    self.key.parameters.message_modulus(),
                    num_blocks_per_integer,
                );
                let second_iter = create_clear_radix_block_iterator(
                    second_message,
                    self.key.parameters.message_modulus(),
                    num_blocks_per_integer,
                );

                iterator_chain =
                    Box::new(first_iter.chain(second_iter)) as Box<dyn Iterator<Item = u64>>;
            }
        }

        for message in message_iter {
            let other_iter = create_clear_radix_block_iterator(
                message,
                self.key.parameters.message_modulus(),
                num_blocks_per_integer,
            );

            iterator_chain = Box::new(iterator_chain.chain(other_iter));
        }

        let ct_list = self.key.encrypt_iter(iterator_chain);
        CompactCiphertextList {
            ct_list,
            num_blocks_per_integer,
        }
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

    pub fn decompress(self) -> CompactPublicKey {
        CompactPublicKey {
            key: self.key.decompress(),
        }
    }
}

impl From<CompressedCompactPublicKey> for CompactPublicKey {
    fn from(value: CompressedCompactPublicKey) -> Self {
        value.decompress()
    }
}
