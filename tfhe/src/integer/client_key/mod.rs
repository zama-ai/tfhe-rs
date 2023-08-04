//! This module implements the generation of the client keys structs
//!
//! Client keys are the keys used to encrypt an decrypt data.
//! These are private and **MUST NOT** be shared.

mod crt;
mod radix;
pub(crate) mod utils;

use crate::core_crypto::prelude::{CastFrom, SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::BlockRecomposer;
use crate::integer::ciphertext::{CompressedCrtCiphertext, CrtCiphertext};
use crate::integer::client_key::utils::i_crt;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::{
    Ciphertext, ClientKey as ShortintClientKey, ShortintParameterSet as ShortintParameters,
};
use serde::{Deserialize, Serialize};
pub use utils::radix_decomposition;

pub use crt::CrtClientKey;
pub use radix::RadixClientKey;

use super::block_decomposition::{DecomposableInto, RecomposableFrom};
use super::ciphertext::{
    CompressedRadixCiphertext, CompressedSignedRadixCiphertext, RadixCiphertext,
    SignedRadixCiphertext,
};

pub trait RecomposableSignedInteger:
    RecomposableFrom<u64>
    + std::ops::Neg<Output = Self>
    + std::ops::Shr<u32, Output = Self>
    + std::ops::BitOrAssign<Self>
    + std::ops::BitOr<Self, Output = Self>
    + std::ops::Mul<Self, Output = Self>
    + CastFrom<Self>
    + SignedNumeric
{
}

impl RecomposableSignedInteger for i8 {}
impl RecomposableSignedInteger for i16 {}
impl RecomposableSignedInteger for i32 {}
impl RecomposableSignedInteger for i64 {}
impl RecomposableSignedInteger for i128 {}

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

impl ClientKey {
    /// Creates a Client Key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key, that can encrypt in
    /// // radix and crt decomposition, where each block of the decomposition
    /// // have over 2 bits of message modulus.
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// ```
    pub fn new<P>(parameter_set: P) -> Self
    where
        P: TryInto<ShortintParameters>,
        <P as TryInto<ShortintParameters>>::Error: std::fmt::Debug,
    {
        Self {
            key: ShortintClientKey::new(parameter_set),
        }
    }

    pub fn parameters(&self) -> crate::shortint::PBSParameters {
        self.key.parameters.pbs_parameters().unwrap()
    }

    /// Encrypts an integer in radix decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    pub fn encrypt_radix<T>(&self, message: T, num_blocks: usize) -> RadixCiphertext
    where
        T: DecomposableInto<u64> + UnsignedNumeric,
    {
        self.encrypt_words_radix(message, num_blocks, crate::shortint::ClientKey::encrypt)
    }

    /// Encrypts an integer in radix decomposition without padding bit
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    pub fn encrypt_radix_without_padding<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding,
        )
    }

    pub fn encrypt_radix_compressed<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_compressed,
        )
    }

    pub fn encrypt_radix_without_padding_compressed<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding_compressed,
        )
    }

    /// Encrypts 64-bits words into a ciphertext in radix decomposition
    ///
    /// The words are assumed to be in little endian order.
    ///
    /// If there are not enough words for the requested num_block,
    /// encryptions of zeros will be appended.
    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: DecomposableInto<u64> + UnsignedNumeric,
        F: Fn(&crate::shortint::ClientKey, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_words_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }

    /// Decrypts a ciphertext encrypting an radix integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    pub fn decrypt_radix<T>(&self, ctxt: &RadixCiphertext) -> T
    where
        T: RecomposableFrom<u64> + UnsignedNumeric,
    {
        self.decrypt_radix_impl(
            &ctxt.blocks,
            crate::shortint::ClientKey::decrypt_message_and_carry,
        )
    }

    /// Decrypts a ciphertext encrypting an radix integer encrypted without padding
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    pub fn decrypt_radix_without_padding<T>(&self, ctxt: &RadixCiphertext) -> T
    where
        T: RecomposableFrom<u64> + UnsignedNumeric,
    {
        self.decrypt_radix_impl(
            &ctxt.blocks,
            crate::shortint::ClientKey::decrypt_message_and_carry_without_padding,
        )
    }

    /// Decrypts a ciphertext in radix decomposition into 64bits
    ///
    /// The words are assumed to be in little endian order.
    fn decrypt_radix_impl<T, F>(
        &self,
        blocks: &[crate::shortint::Ciphertext],
        decrypt_block: F,
    ) -> T
    where
        T: RecomposableFrom<u64>,
        F: Fn(&crate::shortint::ClientKey, &crate::shortint::Ciphertext) -> u64,
    {
        if blocks.is_empty() {
            return T::ZERO;
        }

        let bits_in_block = self.key.parameters.message_modulus().0.ilog2();
        let mut recomposer = BlockRecomposer::<T>::new(bits_in_block);

        for encrypted_block in blocks {
            let decrypted_block = decrypt_block(&self.key, encrypted_block);
            if !recomposer.add_unmasked(decrypted_block) {
                // End of T::BITS reached no need to try more
                // recomposition
                break;
            };
        }

        recomposer.value()
    }

    pub fn encrypt_signed_radix<T>(&self, message: T, num_blocks: usize) -> SignedRadixCiphertext
    where
        T: DecomposableInto<u64> + SignedNumeric,
    {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt,
        )
    }

    pub fn encrypt_signed_radix_without_padding<T>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> SignedRadixCiphertext
    where
        T: DecomposableInto<u64> + SignedNumeric,
    {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding,
        )
    }

    pub fn encrypt_signed_radix_compressed<T: DecomposableInto<u64> + SignedNumeric>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedSignedRadixCiphertext {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_compressed,
        )
    }

    pub fn encrypt_signed_radix_without_padding_compressed<
        T: DecomposableInto<u64> + SignedNumeric,
    >(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedSignedRadixCiphertext {
        encrypt_words_radix_impl(
            &self.key,
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding_compressed,
        )
    }

    pub fn decrypt_signed_radix<T>(&self, ctxt: &SignedRadixCiphertext) -> T
    where
        T: RecomposableSignedInteger,
    {
        self.decrypt_signed_radix_impl(ctxt, crate::shortint::ClientKey::decrypt_message_and_carry)
    }

    pub fn decrypt_signed_radix_impl<T, F>(
        &self,
        ctxt: &SignedRadixCiphertext,
        decrypt_block: F,
    ) -> T
    where
        T: RecomposableSignedInteger,
        F: Fn(&crate::shortint::ClientKey, &crate::shortint::Ciphertext) -> u64,
    {
        let message_modulus = self.parameters().message_modulus().0;
        assert!(message_modulus.is_power_of_two());

        // Decrypting a signed value is the same as decrypting an unsigned value
        // but, in the signed case,
        // we have to take care of the case when the clear type T has more bits
        // than what the ciphertext encrypts.
        let unpadded_value = self.decrypt_radix_impl(&ctxt.blocks, decrypt_block);

        let num_bits_in_message = message_modulus.ilog2();
        let num_bits_in_ctxt = num_bits_in_message * ctxt.blocks.len() as u32;
        if num_bits_in_ctxt >= T::BITS as u32 {
            return unpadded_value;
        }

        let sign_bit_pos = num_bits_in_ctxt - 1;
        let sign_bit_mask = T::cast_from(1u32 << sign_bit_pos);
        let sign_bit = (unpadded_value & sign_bit_mask) >> sign_bit_pos;

        // Creates a padding mask
        // where bits above num_bits_in_ctxt
        // are 1s if sign bit is one else 0
        let padding = (T::MAX * sign_bit) << num_bits_in_ctxt;
        padding | unpadded_value
    }

    /// Encrypts one block.
    ///
    /// This returns a shortint ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    pub fn encrypt_one_block(&self, message: u64) -> Ciphertext {
        self.key.encrypt(message)
    }

    /// Decrypts one block.
    ///
    /// This takes a shortint ciphertext as input.
    pub fn decrypt_one_block(&self, ct: &Ciphertext) -> u64 {
        self.key.decrypt(ct)
    }

    /// Encrypts an integer using crt representation
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3_KS_PBS);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3_KS_PBS);
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

    fn encrypt_crt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        base_vec: Vec<u64>,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::ClientKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }
}
