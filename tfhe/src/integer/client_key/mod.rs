//! This module implements the generation of the client keys structs
//!
//! Client keys are the keys used to encrypt an decrypt data.
//! These are private and **MUST NOT** be shared.

mod crt;
mod radix;
pub(crate) mod utils;

use crate::integer::ciphertext::{
    CompressedCrtCiphertext, CompressedRadixCiphertext, CrtCiphertext, RadixCiphertext,
};
use crate::integer::client_key::utils::i_crt;
use crate::shortint::parameters::MessageModulus;
use crate::shortint::{
    Ciphertext as ShortintCiphertext, ClientKey as ShortintClientKey,
    Parameters as ShortintParameters,
};
use serde::{Deserialize, Serialize};
pub use utils::radix_decomposition;

use crate::integer::U256;
pub use crt::CrtClientKey;
pub use radix::RadixClientKey;

/// A structure containing the client key, which must be kept secret.
///
/// This key can be used to encrypt both in Radix and CRT
/// decompositions.
///
/// Using this key, for both decompositions, each block will
/// use the same crypto parameters.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ClientKey {
    pub(crate) key: ShortintClientKey,
}

impl From<ShortintClientKey> for ClientKey {
    fn from(key: ShortintClientKey) -> Self {
        Self { key }
    }
}

impl From<ClientKey> for ShortintClientKey {
    fn from(key: ClientKey) -> ShortintClientKey {
        key.key
    }
}

impl AsRef<ClientKey> for ClientKey {
    fn as_ref(&self) -> &ClientKey {
        self
    }
}

pub trait ClearText {
    fn as_words(&self) -> &[u64];

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

impl ClientKey {
    /// Creates a Client Key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key, that can encrypt in
    /// // radix and crt decomposition, where each block of the decomposition
    /// // have over 2 bits of message modulus.
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// ```
    pub fn new(parameter_set: ShortintParameters) -> Self {
        Self {
            key: ShortintClientKey::new(parameter_set),
        }
    }

    pub fn parameters(&self) -> ShortintParameters {
        self.key.parameters
    }

    /// Encrypts an integer in radix decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix<T: ClearText>(&self, message: T, num_blocks: usize) -> RadixCiphertext {
        self.encrypt_words_radix(
            message.as_words(),
            num_blocks,
            crate::shortint::ClientKey::encrypt,
        )
    }

    pub fn encrypt_radix_compressed<T: ClearText>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message.as_words(),
            num_blocks,
            crate::shortint::ClientKey::encrypt_compressed,
        )
    }

    pub fn encrypt_radix_without_padding_compressed<T: ClearText>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message.as_words(),
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding_compressed,
        )
    }

    /// Encrypts an integer in radix decomposition without padding bit
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message.as_words(),
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding,
        )
    }

    /// Encrypts 64-bits words into a ciphertext in radix decomposition
    ///
    /// The words are assumed to be in little endian order.
    ///
    /// If there are not enough words for the requested num_block,
    /// encryptions of zeros will be appended.
    pub fn encrypt_words_radix<Block, RadixCiphertextType, F>(
        &self,
        message_words: &[u64],
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        F: Fn(&crate::shortint::ClientKey, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        let mask = (self.key.parameters.message_modulus.0 - 1) as u128;
        let block_modulus = self.key.parameters.message_modulus.0 as u128;

        let mut blocks = Vec::with_capacity(num_blocks);
        let mut message_block_iter = message_words.iter().copied();

        let mut source = 0u128; // stores the bits of the word to be encrypted in one of the iteration
        let mut valid_until_power = 1; // 2^0 = 1, start with nothing valid
        let mut current_power = 1; // where the next bits to encrypt starts
        for _ in 0..num_blocks {
            // Are we going to encrypt bits that are not valid ?
            // If so, discard already encrypted bits and fetch bits form the input words
            if (current_power * block_modulus) >= valid_until_power {
                source /= current_power;
                valid_until_power /= current_power;

                source += message_block_iter
                    .next()
                    .map(u128::from)
                    .unwrap_or_default()
                    * valid_until_power;

                current_power = 1;
                valid_until_power <<= 64;
            }

            let block_value = (source & (mask * current_power)) / current_power;
            let ct = encrypt_block(&self.key, block_value as u64);
            blocks.push(ct);

            current_power *= block_modulus;
        }

        RadixCiphertextType::from(blocks)
    }

    /// Encrypts one block.
    ///
    /// This returns a shortint ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 2_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_one_block(msg);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_one_block(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_one_block(&self, message: u64) -> ShortintCiphertext {
        self.key.encrypt(message)
    }

    /// Decrypts one block.
    ///
    /// This takes a shortint ciphertext as input.
    pub fn decrypt_one_block(&self, ct: &ShortintCiphertext) -> u64 {
        self.key.decrypt(ct)
    }

    /// Decrypts a ciphertext encrypting an radix integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix<T: ClearText + Default>(&self, ctxt: &RadixCiphertext) -> T {
        let mut res = T::default();
        self.decrypt_radix_into(ctxt, &mut res);
        res
    }

    pub fn decrypt_radix_into<T: ClearText>(&self, ctxt: &RadixCiphertext, out: &mut T) {
        self.decrypt_radix_into_words(
            ctxt,
            out.as_words_mut(),
            crate::shortint::ClientKey::decrypt_message_and_carry,
        );
    }

    /// Decrypts a ciphertext encrypting an radix integer encrypted without padding
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix_without_padding(&self, ctxt: &RadixCiphertext) -> u64 {
        let mut res = 0u64;
        self.decrypt_radix_into_words(
            ctxt,
            res.as_words_mut(),
            crate::shortint::ClientKey::decrypt_message_and_carry_without_padding,
        );
        res
    }

    /// Decrypts a ciphertext in radix decomposition into 64bits
    ///
    /// The words are assumed to be in little endian order.
    pub fn decrypt_radix_into_words<F>(
        &self,
        ctxt: &RadixCiphertext,
        clear_words: &mut [u64],
        decrypt_block: F,
    ) where
        F: Fn(&crate::shortint::ClientKey, &crate::shortint::Ciphertext) -> u64,
    {
        let mut cipher_blocks_iter = ctxt.blocks.iter();
        let mut current = 0u128;
        let mut power = 1u128;
        let mut power_excess = 1;
        for current_clear_word in clear_words.iter_mut() {
            for cipher_block in cipher_blocks_iter.by_ref() {
                let block_value = decrypt_block(&self.key, cipher_block) as u128;

                let shifted_block_value = block_value * power * power_excess;
                current += shifted_block_value;

                let new_power = power * self.key.parameters.message_modulus.0 as u128;
                let pow_dif = (new_power * power_excess) / (1u128 << 64);

                if pow_dif >= 1 {
                    power_excess = pow_dif;
                    power = 1;
                    break;
                } else {
                    power = new_power;
                }
            }

            if power == 1 {
                *current_clear_word = (current & u128::from(u64::MAX)) as u64;
                current = current.wrapping_shr(64);
            } else {
                *current_clear_word = (current & ((power * power_excess) - 1)) as u64;
            }
        }
    }

    /// Encrypts an integer using crt representation
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::ClientKey::encrypt_with_message_modulus,
        )
    }

    pub fn encrypt_crt_compressed(
        &self,
        message: u64,
        base_vec: Vec<u64>,
    ) -> CompressedCrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::ClientKey::encrypt_with_message_modulus_compressed,
        )
    }

    /// Decrypts an integer in crt decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let mut cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    ///
    /// // Encryption:
    /// let mut ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_crt(&self, ctxt: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = Vec::with_capacity(ctxt.blocks.len());

        // Decrypting each block individually
        for (c_i, b_i) in ctxt.blocks.iter().zip(ctxt.moduli.iter()) {
            // decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.decrypt_message_and_carry(c_i) % b_i);
        }

        // Computing the inverse CRT to recompose the message
        let result = i_crt(&ctxt.moduli, &val);

        let whole_modulus: u64 = ctxt.moduli.iter().copied().product();

        result % whole_modulus
    }

    /// Encrypts a small integer message using the client key and some moduli without padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption of one message:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_native_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt(msg, moduli.0 as u8)
        })
    }

    pub fn encrypt_native_crt_compressed(
        &self,
        message: u64,
        base_vec: Vec<u64>,
    ) -> CompressedCrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt_compressed(msg, moduli.0 as u8)
        })
    }

    /// Decrypts a ciphertext encrypting an integer message with some moduli basis without
    /// padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// // Encryption of one message:
    /// let mut ct = cks.encrypt_native_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_native_crt(&self, ct: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = vec![];

        //Decrypting each block individually
        for (c_i, b_i) in ct.blocks.iter().zip(ct.moduli.iter()) {
            //decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.decrypt_message_native_crt(c_i, *b_i as u8));
        }

        //Computing the inverse CRT to recompose the message
        let result = i_crt(&ct.moduli, &val);

        let whole_modulus: u64 = ct.moduli.iter().copied().product();

        result % whole_modulus
    }

    pub fn encrypt_crt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        base_vec: Vec<u64>,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::ClientKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        let mut ctxt_vect = Vec::with_capacity(base_vec.len());

        // Put each decomposition into a new ciphertext
        for modulus in base_vec.iter().copied() {
            // encryption
            let ct = encrypt_block(&self.key, message, MessageModulus(modulus as usize));

            ctxt_vect.push(ct);
        }

        CrtCiphertextType::from((ctxt_vect, base_vec))
    }
}
