use super::U256;
use crate::shortint::parameters::MessageModulus;

pub trait AsLittleEndianWords {
    type Iter<'a>: Iterator<Item = &'a u64>
    where
        Self: 'a;

    type IterMut<'a>: Iterator<Item = &'a mut u64>
    where
        Self: 'a;

    fn as_little_endian_iter(&self) -> Self::Iter<'_>;

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_>;
}

impl AsLittleEndianWords for u64 {
    type Iter<'a> = std::slice::Iter<'a, u64>;

    type IterMut<'a> = std::slice::IterMut<'a, u64>;

    fn as_little_endian_iter(&self) -> Self::Iter<'_> {
        let u64_slc = std::slice::from_ref(self);

        u64_slc.iter()
    }

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_> {
        let u64_slc = std::slice::from_mut(self);

        u64_slc.iter_mut()
    }
}

#[cfg(target_endian = "little")]
impl AsLittleEndianWords for u128 {
    type Iter<'a> = std::slice::Iter<'a, u64>;

    type IterMut<'a> = std::slice::IterMut<'a, u64>;

    fn as_little_endian_iter(&self) -> Self::Iter<'_> {
        let slc = std::slice::from_ref(self);

        let u64_slc = unsafe { std::slice::from_raw_parts(slc.as_ptr() as *const u64, 2) };

        u64_slc.iter()
    }

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_> {
        let slc = std::slice::from_mut(self);

        let u64_slc = unsafe { std::slice::from_raw_parts_mut(slc.as_ptr() as *mut u64, 2) };

        u64_slc.iter_mut()
    }
}

#[cfg(target_endian = "big")]
impl AsLittleEndianWords for u128 {
    type Iter<'a> = core::iter::Rev<std::slice::Iter<'a, u64>>;

    type IterMut<'a> = core::iter::Rev<std::slice::IterMut<'a, u64>>;

    fn as_little_endian_iter(&self) -> Self::Iter<'_> {
        let slc = std::slice::from_ref(self);

        let u64_slc = unsafe { std::slice::from_raw_parts(slc.as_ptr() as *const u64, 2) };

        u64_slc.iter().rev()
    }

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_> {
        let slc = std::slice::from_mut(self);

        let u64_slc = unsafe { std::slice::from_raw_parts_mut(slc.as_ptr() as *mut u64, 2) };

        u64_slc.iter_mut().rev()
    }
}

#[cfg(target_endian = "little")]
impl AsLittleEndianWords for U256 {
    type Iter<'a> = std::slice::Iter<'a, u64>;

    type IterMut<'a> = std::slice::IterMut<'a, u64>;

    fn as_little_endian_iter(&self) -> Self::Iter<'_> {
        self.0.as_slice().iter()
    }

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_> {
        self.0.as_mut_slice().iter_mut()
    }
}

#[cfg(target_endian = "big")]
impl AsLittleEndianWords for U256 {
    type Iter<'a> = core::iter::Rev<std::slice::Iter<'a, u64>>;

    type IterMut<'a> = core::iter::Rev<std::slice::IterMut<'a, u64>>;

    fn as_little_endian_iter(&self) -> Self::Iter<'_> {
        self.0.as_slice().iter().rev()
    }

    fn as_little_endian_iter_mut(&mut self) -> Self::IterMut<'_> {
        self.0.as_mut_slice().iter_mut().rev()
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
pub(crate) fn encrypt_words_radix_impl<BlockKey, Block, RadixCiphertextType, T, F>(
    encrypting_key: &BlockKey,
    message_words: T,
    num_blocks: usize,
    encrypt_block: F,
) -> RadixCiphertextType
where
    T: AsLittleEndianWords,
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

    let mut message_block_iter = message_words.as_little_endian_iter().copied();

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
