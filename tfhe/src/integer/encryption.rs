use super::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::shortint::parameters::MessageModulus;

pub(crate) trait KnowsMessageModulus {
    fn message_modulus(&self) -> MessageModulus;
}

impl KnowsMessageModulus for crate::shortint::ClientKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl KnowsMessageModulus for crate::shortint::PublicKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl KnowsMessageModulus for crate::shortint::CompressedPublicKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl KnowsMessageModulus for crate::shortint::CompactPublicKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus()
    }
}

impl KnowsMessageModulus for crate::shortint::ServerKey {
    fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }
}

/// Encrypts an arbitrary sized number under radix decomposition
///
/// This function encrypts a number represented as a slice of 64bits words
/// into an integer ciphertext in radix decomposition
///
/// - Each block in encrypted under the same `encrypting_key`.
/// - `message_words` is expected to be in the current machine byte order.
/// - `num_block` is the number of radix block the final ciphertext will have.
pub(crate) fn encrypt_words_radix_impl<BlockKey, Block, RadixCiphertextType, T, F>(
    encrypting_key: &BlockKey,
    message: T,
    num_blocks: usize,
    encrypt_block: F,
) -> RadixCiphertextType
where
    T: DecomposableInto<u64>,
    BlockKey: KnowsMessageModulus,
    F: Fn(&BlockKey, u64) -> Block,
    RadixCiphertextType: From<Vec<Block>>,
{
    let message_modulus = encrypting_key.message_modulus();
    let clear_block_iterator =
        create_clear_radix_block_iterator(message, message_modulus, num_blocks);

    let blocks = clear_block_iterator
        .map(|clear_block| encrypt_block(encrypting_key, clear_block))
        .collect::<Vec<_>>();

    RadixCiphertextType::from(blocks)
}

pub(crate) fn create_clear_radix_block_iterator<T>(
    message: T,
    message_modulus: MessageModulus,
    num_blocks: usize,
) -> impl Iterator<Item = u64>
where
    T: DecomposableInto<u64>,
{
    let bits_in_block = message_modulus.0.ilog2();
    let decomposer = BlockDecomposer::new(message, bits_in_block);

    decomposer
        .iter_as::<u64>()
        .chain(std::iter::repeat(0u64))
        .take(num_blocks)
}

pub(crate) fn encrypt_crt<BlockKey, Block, CrtCiphertextType, F>(
    encrypting_key: &BlockKey,
    message: u64,
    base_vec: Vec<u64>,
    encrypt_block: F,
) -> CrtCiphertextType
where
    F: Fn(&BlockKey, u64, MessageModulus) -> Block,
    CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
{
    let mut ctxt_vect = Vec::with_capacity(base_vec.len());

    // Put each decomposition into a new ciphertext
    for modulus in base_vec.iter().copied() {
        // encryption
        let ct = encrypt_block(encrypting_key, message, MessageModulus(modulus as usize));

        ctxt_vect.push(ct);
    }

    CrtCiphertextType::from((ctxt_vect, base_vec))
}
