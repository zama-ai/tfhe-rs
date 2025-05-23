use super::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::shortint::parameters::MessageModulus;

pub(crate) trait KnowsMessageModulus {
    fn message_modulus(&self) -> MessageModulus;
}

impl KnowsMessageModulus for crate::shortint::ClientKey {
    fn message_modulus(&self) -> MessageModulus {
        self.parameters().message_modulus()
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
        self.parameters.message_modulus
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

/// Same as [`encrypt_words_radix_impl`] with an encryption function working directly on several
/// plaintexts at once.
pub(crate) fn encrypt_many_words_radix_impl<BlockKey, Block, RadixCiphertextType, T, F>(
    encrypting_key: &BlockKey,
    message: T,
    num_blocks: usize,
    encrypt_blocks: F,
) -> RadixCiphertextType
where
    T: DecomposableInto<u64>,
    BlockKey: KnowsMessageModulus,
    F: Fn(&BlockKey, ClearRadixBlockIterator<T>) -> Vec<Block>,
    RadixCiphertextType: From<Vec<Block>>,
{
    let message_modulus = encrypting_key.message_modulus();
    let clear_block_iterator =
        create_clear_radix_block_iterator(message, message_modulus, num_blocks);

    let blocks = encrypt_blocks(encrypting_key, clear_block_iterator);

    RadixCiphertextType::from(blocks)
}

// We need to concretize the iterator type to be able to pass callbacks consuming the iterator,
// having an opaque return impl Iterator does not allow to take callbacks at this moment, not sure
// the Fn(impl Trait) syntax can be made to work nicely with the rest of the language
pub(crate) type ClearRadixBlockIterator<T> = std::iter::Map<BlockDecomposer<T>, fn(T) -> u64>;

pub(crate) fn create_clear_radix_block_iterator<T>(
    message: T,
    message_modulus: MessageModulus,
    num_blocks: usize,
) -> ClearRadixBlockIterator<T>
where
    T: DecomposableInto<u64>,
{
    let bits_in_block = message_modulus.0.ilog2();
    BlockDecomposer::with_block_count(message, bits_in_block, num_blocks).iter_as::<u64>()
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
        let ct = encrypt_block(encrypting_key, message, MessageModulus(modulus));

        ctxt_vect.push(ct);
    }

    CrtCiphertextType::from((ctxt_vect, base_vec))
}

pub(crate) type CrtManyMessageModulusIterator =
    core::iter::Map<std::vec::IntoIter<u64>, fn(u64) -> MessageModulus>;

pub(crate) fn encrypt_many_crt<BlockKey, Block, CrtCiphertextType, F>(
    encrypting_key: &BlockKey,
    message: u64,
    base_vec: Vec<u64>,
    encrypt_blocks: F,
) -> CrtCiphertextType
where
    F: Fn(&BlockKey, u64, CrtManyMessageModulusIterator) -> Vec<Block>,
    CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
{
    let ctxt_vect = encrypt_blocks(
        encrypting_key,
        message,
        base_vec.clone().into_iter().map(MessageModulus),
    );

    CrtCiphertextType::from((ctxt_vect, base_vec))
}
