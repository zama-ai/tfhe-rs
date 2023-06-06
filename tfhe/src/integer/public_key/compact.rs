use serde::{Deserialize, Serialize};

use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::{CompactCiphertextList, RadixCiphertext};
use crate::integer::encryption::{create_clear_radix_block_iterator, encrypt_words_radix_impl};
use crate::integer::ClientKey;
use crate::shortint::ciphertext::{BootstrapKeyswitch, KeyswitchBootstrap};
use crate::shortint::{
    CompactPublicKeyBase as ShortintCompactPublicKeyBase,
    CompressedCompactPublicKeyBase as ShortintCompressedCompactPublicKeyBase, PBSOrderMarker,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactPublicKeyBase<OpOrder: PBSOrderMarker> {
    pub(crate) key: ShortintCompactPublicKeyBase<OpOrder>,
}

pub type CompactPublicKeyBig = CompactPublicKeyBase<KeyswitchBootstrap>;
pub type CompactPublicKeySmall = CompactPublicKeyBase<BootstrapKeyswitch>;

impl<OpOrder: PBSOrderMarker> CompactPublicKeyBase<OpOrder> {
    pub fn new(client_key: &ClientKey) -> Self {
        let key = ShortintCompactPublicKeyBase::<OpOrder>::new(&client_key.key);
        Self { key }
    }

    pub fn try_new(client_key: &ClientKey) -> Option<Self> {
        let key = ShortintCompactPublicKeyBase::<OpOrder>::try_new(&client_key.key)?;
        Some(Self { key })
    }

    pub fn encrypt_radix<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext<OpOrder> {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            ShortintCompactPublicKeyBase::encrypt,
        )
    }

    pub fn encrypt_radix_compact<T: DecomposableInto<u64>>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompactCiphertextList<OpOrder> {
        let clear_block_iter = create_clear_radix_block_iterator(
            message,
            self.key.parameters.message_modulus(),
            num_blocks,
        );

        let ct_list = self.key.encrypt_iter(clear_block_iter);
        CompactCiphertextList {
            ct_list,
            num_blocks,
        }
    }

    pub fn encrypt_slice_radix_compact<T: DecomposableInto<u64>>(
        &self,
        messages: &[T],
        num_blocks: usize,
    ) -> CompactCiphertextList<OpOrder> {
        self.encrypt_iter_radix_compact(messages.iter().copied(), num_blocks)
    }

    pub fn encrypt_iter_radix_compact<T: DecomposableInto<u64>>(
        &self,
        mut message_iter: impl Iterator<Item = T>,
        num_blocks: usize,
    ) -> CompactCiphertextList<OpOrder> {
        let mut iterator_chain;
        match (message_iter.next(), message_iter.next()) {
            (None, None) => panic!("At least one message is required"),
            (None, Some(_)) => unreachable!(),
            (Some(first_message), None) => {
                // Cannot form a chain
                return self.encrypt_radix_compact(first_message, num_blocks);
            }
            (Some(first_message), Some(second_message)) => {
                let first_iter = create_clear_radix_block_iterator(
                    first_message,
                    self.key.parameters.message_modulus(),
                    num_blocks,
                );
                let second_iter = create_clear_radix_block_iterator(
                    second_message,
                    self.key.parameters.message_modulus(),
                    num_blocks,
                );

                iterator_chain =
                    Box::new(first_iter.chain(second_iter)) as Box<dyn Iterator<Item = u64>>;
            }
        }

        for message in message_iter {
            let other_iter = create_clear_radix_block_iterator(
                message,
                self.key.parameters.message_modulus(),
                num_blocks,
            );

            iterator_chain = Box::new(iterator_chain.chain(other_iter));
        }

        let ct_list = self.key.encrypt_iter(iterator_chain);
        CompactCiphertextList {
            ct_list,
            num_blocks,
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
pub struct CompressedCompactPublicKeyBase<OpOrder: PBSOrderMarker> {
    pub(crate) key: ShortintCompressedCompactPublicKeyBase<OpOrder>,
}

pub type CompressedCompactPublicKeyBig = CompressedCompactPublicKeyBase<KeyswitchBootstrap>;
pub type CompressedCompactPublicKeySmall = CompressedCompactPublicKeyBase<BootstrapKeyswitch>;

impl<OpOrder: PBSOrderMarker> CompressedCompactPublicKeyBase<OpOrder> {
    pub fn new(client_key: &ClientKey) -> Self {
        let key = ShortintCompressedCompactPublicKeyBase::<OpOrder>::new(&client_key.key);
        Self { key }
    }

    pub fn decompress(self) -> CompactPublicKeyBase<OpOrder> {
        CompactPublicKeyBase {
            key: self.key.decompress(),
        }
    }
}

impl<OpOrder: PBSOrderMarker> From<CompressedCompactPublicKeyBase<OpOrder>>
    for CompactPublicKeyBase<OpOrder>
{
    fn from(value: CompressedCompactPublicKeyBase<OpOrder>) -> Self {
        value.decompress()
    }
}
