use super::U256;
use crate::shortint::parameters::MessageModulus;

pub trait ClearText {
    // words are expected to be in the target endian
    fn as_words(&self) -> &[u64];

    // words are expected to be in the target endian
    fn as_words_mut(&mut self) -> &mut [u64];
}

impl ClearText for u64 {
    fn as_words(&self) -> &[u64] {
        std::slice::from_ref(self)
    }

    fn as_words_mut(&mut self) -> &mut [u64] {
        std::slice::from_mut(self)
    }
}

impl ClearText for u128 {
    fn as_words(&self) -> &[u64] {
        let u128_slc = std::slice::from_ref(self);
        unsafe { std::slice::from_raw_parts(u128_slc.as_ptr() as *const u64, 2) }
    }

    fn as_words_mut(&mut self) -> &mut [u64] {
        let u128_slc = std::slice::from_mut(self);
        unsafe { std::slice::from_raw_parts_mut(u128_slc.as_mut_ptr() as *mut u64, 2) }
    }
}

impl ClearText for U256 {
    fn as_words(&self) -> &[u64] {
        let u128_slc = self.0.as_slice();
        unsafe { std::slice::from_raw_parts(u128_slc.as_ptr() as *const u64, 4) }
    }

    fn as_words_mut(&mut self) -> &mut [u64] {
        let u128_slc = self.0.as_mut_slice();
        unsafe { std::slice::from_raw_parts_mut(u128_slc.as_mut_ptr() as *mut u64, 4) }
    }
}

pub(crate) trait BlockEncryptionKey {
    fn parameters(&self) -> &crate::shortint::Parameters;
}

impl BlockEncryptionKey for crate::shortint::ClientKey {
    fn parameters(&self) -> &crate::shortint::Parameters {
        &self.parameters
    }
}

impl BlockEncryptionKey for crate::shortint::PublicKey {
    fn parameters(&self) -> &crate::shortint::Parameters {
        &self.parameters
    }
}

impl BlockEncryptionKey for crate::shortint::CompressedPublicKey {
    fn parameters(&self) -> &crate::shortint::Parameters {
        &self.parameters
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
pub(crate) fn encrypt_words_radix_impl<BlockKey, Block, RadixCiphertextType, F>(
    encrypting_key: &BlockKey,
    message_words: &[u64],
    num_blocks: usize,
    encrypt_block: F,
) -> RadixCiphertextType
where
    BlockKey: BlockEncryptionKey,
    F: Fn(&BlockKey, u64) -> Block,
    RadixCiphertextType: From<Vec<Block>>,
{
    // General idea:
    // Use as a bit buffer, and "cursors" to track the start of next block of bits to encrypt
    // and until which bit the bits are valid / not garbage.
    // e.g:
    // source: [b0, b1, ..., b64, b65..., b128]
    //              ^             ^
    //              |             |-> valid_until_power (starting from this bit,
    //              |                 bit values are not valid and should not be encrypted)
    //              |-> current_power (start of next block of bits to encrypt (inclusive))

    let mask = (encrypting_key.parameters().message_modulus.0 - 1) as u128;
    let block_modulus = encrypting_key.parameters().message_modulus.0 as u128;

    let mut blocks = Vec::with_capacity(num_blocks);

    #[cfg(target_endian = "little")]
    let mut message_block_iter = message_words.iter().copied();
    #[cfg(target_endian = "big")]
    let mut message_block_iter = message_words.iter().rev().copied();

    let mut bit_buffer = 0u128; // stores the bits of the word to be encrypted in one of the iteration
    let mut valid_until_power = 1; // 2^0 = 1, start with nothing valid
    let mut current_power = 1; // where the next bits to encrypt starts
    for _ in 0..num_blocks {
        if (current_power * block_modulus) >= valid_until_power {
            // We are going to encrypt bits that are not valid.
            // e.g:
            // source: [b0, ..., b63, b64, b65, b66, b67,..., b128]
            //                   ^         ^          ^
            //                   |         |          |-> (current_power * block_modulus)
            //                   |         |              = end of bits to encrypt (not inclusive)
            //                   |         |-> valid_until_power
            //                   |             (starting from this bit, bit values are not valid)
            //                   |-> current_power = start of next block of bits to encrypt

            // 1: shift (remove) bits we know we have already encrypted
            // source: [b0, b1, b2, b3, b4,..., b128]
            //          ^       ^       ^
            //          |       |       |->  (current_power * block_modulus)
            //          |       |-> valid_until_power
            //          |-> current_power
            bit_buffer /= current_power;
            valid_until_power /= current_power;
            current_power = 1;

            // 2: Append next word (or zero) to the source
            // source: [b0, b1, b2, b3, b4,..., b67, b128]
            //          ^               ^        ^
            //          |               |        |-> valid_until_power
            //          |               |-> (current_power * block_modulus)
            //          |-> current_power
            bit_buffer += message_block_iter
                .next()
                .map(u128::from)
                .unwrap_or_default()
                * valid_until_power;
            valid_until_power <<= 64;
        }

        let block_value = (bit_buffer & (mask * current_power)) / current_power;
        let ct = encrypt_block(encrypting_key, block_value as u64);
        blocks.push(ct);

        current_power *= block_modulus;
    }

    RadixCiphertextType::from(blocks)
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
