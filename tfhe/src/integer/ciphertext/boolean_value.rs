use super::{IntegerCiphertext, IntegerRadixCiphertext};
use crate::integer::{RadixCiphertext, ServerKey};
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::shortint::Ciphertext;
use serde::{Deserialize, Serialize};

/// Wrapper type used to signal that the inner value encrypts 0 or 1
///
/// Since values ares encrypted, it is not possible to know whether a
/// ciphertext encrypts a boolean value (0 or 1). However some algorithms
/// require that the ciphertext does indeed encrypt a boolean value.
///
/// This wrapper serves as making it explicit that it is known that the value
/// encrypted is 0 or 1. And that if a function taking a BooleanBlock as input
/// returns incorrect value, it may be due to the value not really being 0 or 1.
///
/// Also some function such as comparisons are known to return an encrypted value
/// that is either 0 or 1, and thus return a Ciphertext wrapped in a [BooleanBlock].
///
/// # Examples
/// ## Converting a [BooleanBlock] to a [RadixCiphertext]
///
/// ```
/// use tfhe::integer::{gen_keys_radix, BooleanBlock};
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
///
/// // We have 4 * 2 = 8 bits of message
/// let size = 4;
/// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
///
/// let a = 128u8;
/// let b = 55u8;
///
/// let ct_a = cks.encrypt(a);
/// let ct_b = cks.encrypt(b);
///
/// let ct_res = sks.ge_parallelized(&ct_a, &ct_b);
/// // Convert the boolean value to a RadixCiphertext of size blocks
/// // so we can use it in operations
/// let ct_res = ct_res.into_radix(size, &sks);
/// // Decrypt:
/// let dec: u8 = cks.decrypt(&ct_res);
/// assert_eq!(u8::from(a >= b), dec);
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BooleanBlock(pub(crate) Ciphertext);

impl BooleanBlock {
    /// Creates a new BooleanBlock without checks.
    ///
    /// You have to be sure the ciphertext encrypts 0 or 1 otherwise
    /// functions expecting a BooleanBlock could result in wrong computation
    pub fn new_unchecked(block: Ciphertext) -> Self {
        Self(block)
    }

    /// Creates a new BooleanBlock, but does some checks to see
    /// if it seems plausible that it encrypts a boolean.
    ///
    /// Sometimes these checks may prove to be too strict,
    /// and you might need to use [BooleanBlock::new_unchecked] if you know it actually does encrypt
    /// a boolean, or [BooleanBlock::convert] if there is some uncertainty.
    pub fn try_new<T>(ct: &T) -> Option<Self>
    where
        T: IntegerRadixCiphertext,
    {
        if ct.holds_boolean_value() {
            Some(Self(ct.blocks()[0].clone()))
        } else {
            None
        }
    }

    /// Creates a new BooleanBlock by doing a PBS to ensure the result in either O or 1
    ///
    /// It is equivalent to doing `let b: bool = value != 0`
    ///
    /// # Examples
    /// ## Converting a [BooleanBlock] to a [RadixCiphertext]
    ///
    /// ```
    /// use tfhe::integer::{gen_keys_radix, BooleanBlock};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let a = 128u8;
    /// let ct_a = cks.encrypt(a);
    ///
    /// let ct_b = BooleanBlock::convert(&ct_a, &sks);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt_bool(&ct_b);
    /// assert_eq!(a != 0, dec);
    /// ```
    pub fn convert<T>(ct: &T, sks: &ServerKey) -> Self
    where
        T: IntegerRadixCiphertext,
    {
        if ct.holds_boolean_value() {
            let block = ct.blocks()[0].clone();
            Self(block)
        } else {
            sks.scalar_ne_parallelized(ct, 0)
        }
    }

    /// Consumes the BooleanBlock to return its inner ciphertext
    pub fn into_inner(self) -> Ciphertext {
        self.0
    }

    /// Consumes and converts the BooleanBlock to a [RadixCiphertext] / [SignedRadixCiphertext]
    /// with the given number of blocks.
    ///
    /// [SignedRadixCiphertext]: crate::integer::SignedRadixCiphertext
    pub fn into_radix<T>(self, num_blocks: usize, sks: &ServerKey) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut radix_ct = RadixCiphertext::from_blocks(vec![self.0]);
        let missing_blocks = num_blocks.saturating_sub(1);
        sks.extend_radix_with_trivial_zero_blocks_msb_assign(&mut radix_ct, missing_blocks);
        T::from_blocks(radix_ct.blocks)
    }

    /// Decrypts a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::{gen_keys_radix, RadixCiphertext, SignedRadixCiphertext};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // 8 bits
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
    ///
    /// let msg = false;
    /// let msg2 = true;
    ///
    /// // Trivial encryption
    /// let trivial_ct = sks.create_trivial_boolean_block(msg);
    /// let non_trivial_ct = cks.encrypt_bool(msg2);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// assert_eq!(Ok(msg), res);
    ///
    /// let res = non_trivial_ct.decrypt_trivial();
    /// matches!(res, Err(_));
    /// ```
    pub fn decrypt_trivial(&self) -> Result<bool, NotTrivialCiphertextError> {
        let value = self.0.decrypt_trivial()?;
        Ok(value != 0)
    }
}

impl AsRef<Ciphertext> for BooleanBlock {
    fn as_ref(&self) -> &Ciphertext {
        &self.0
    }
}
