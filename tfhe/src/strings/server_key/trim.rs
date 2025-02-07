use crate::integer::prelude::*;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey as IntegerServerKey};
use crate::strings::ciphertext::{FheAsciiChar, FheString};
use crate::strings::server_key::{FheStringIsEmpty, FheStringIterator, FheStringLen, ServerKey};
use rayon::prelude::*;
use std::borrow::Borrow;

pub struct SplitAsciiWhitespace {
    state: FheString,
    current_mask: Option<FheString>,
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for SplitAsciiWhitespace {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        let sk_integer = sk.inner();

        if self.state.is_empty() {
            return (
                FheString::empty(),
                sk_integer.create_trivial_boolean_block(false),
            );
        }

        // If we aren't in the first next call `current_mask` is some
        if self.current_mask.is_some() {
            self.remaining_string(sk);
        }

        let state_after_trim = sk.trim_start(&self.state);
        self.state = state_after_trim.clone();

        rayon::join(
            || self.create_and_apply_mask(sk),
            || {
                // If state after trim_start is empty it means the remaining string was either
                // empty or only whitespace. Hence, there are no more elements to return
                if let FheStringIsEmpty::Padding(val) = sk.is_empty(&state_after_trim) {
                    sk_integer.boolean_bitnot(&val)
                } else {
                    panic!("Empty str case was handled so 'state_after_trim' is padded")
                }
            },
        )
    }
}

impl SplitAsciiWhitespace {
    // The mask contains 255u8 until we find some whitespace, then will be 0u8
    fn create_and_apply_mask<T: Borrow<IntegerServerKey> + Sync>(
        &mut self,
        sk: &ServerKey<T>,
    ) -> FheString {
        let sk_integer = sk.inner();

        let mut mask = self.state.clone();
        let mut result = self.state.clone();

        let mut prev_was_not = sk_integer.create_trivial_boolean_block(true);
        for char in mask.chars_mut().iter_mut() {
            let mut is_not_ws = sk.is_not_whitespace(char);
            sk_integer.boolean_bitand_assign(&mut is_not_ws, &prev_was_not);

            let mut mask_u8 = is_not_ws
                .clone()
                .into_radix(sk.num_ascii_blocks(), sk_integer);

            // 0u8 is kept the same, but 1u8 is transformed into 255u8
            sk_integer.scalar_sub_assign_parallelized(&mut mask_u8, 1);
            sk_integer.bitnot_assign(&mut mask_u8);

            *char.ciphertext_mut() = mask_u8;

            prev_was_not = is_not_ws;
        }

        // Apply the mask to get the result
        result
            .chars_mut()
            .par_iter_mut()
            .zip(mask.chars().par_iter())
            .for_each(|(char, mask_u8)| {
                sk_integer.bitand_assign_parallelized(char.ciphertext_mut(), mask_u8.ciphertext());
            });

        self.current_mask = Some(mask);

        result
    }

    // Shifts the string left to get the remaining string (starting at the next first whitespace)
    fn remaining_string<T: Borrow<IntegerServerKey> + Sync>(&mut self, sk: &ServerKey<T>) {
        let sk_integer = sk.inner();

        let mask = self.current_mask.as_ref().unwrap();

        let mut number_of_trues: RadixCiphertext = sk_integer.create_trivial_zero_radix(16);
        for mask_u8 in mask.chars() {
            let is_true = sk_integer.scalar_eq_parallelized(mask_u8.ciphertext(), 255u8);

            let num_blocks = number_of_trues.blocks().len();

            sk_integer.add_assign_parallelized(
                &mut number_of_trues,
                &is_true.into_radix(num_blocks, sk_integer),
            );
        }

        let padded = self.state.is_padded();

        self.state = sk.left_shift_chars(&self.state, &number_of_trues);

        if padded {
            self.state.set_is_padded(true);
        } else {
            // If it was not padded now we cannot assume it's not padded (because of the left shift)
            // so we add a null to ensure it's always padded
            self.state.append_null(sk);
        }
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    // As specified in https://doc.rust-lang.org/core/primitive.char.html#method.is_ascii_whitespace
    fn is_whitespace(&self, char: &FheAsciiChar, or_null: bool) -> BooleanBlock {
        let sk = self.inner();

        let (((is_space, is_tab), (is_new_line, is_form_feed)), (is_carriage_return, op_is_null)) =
            rayon::join(
                || {
                    rayon::join(
                        || {
                            rayon::join(
                                || sk.scalar_eq_parallelized(char.ciphertext(), 0x20u8),
                                || sk.scalar_eq_parallelized(char.ciphertext(), 0x09u8),
                            )
                        },
                        || {
                            rayon::join(
                                || sk.scalar_eq_parallelized(char.ciphertext(), 0x0Au8),
                                || sk.scalar_eq_parallelized(char.ciphertext(), 0x0Cu8),
                            )
                        },
                    )
                },
                || {
                    rayon::join(
                        || sk.scalar_eq_parallelized(char.ciphertext(), 0x0Du8),
                        || or_null.then_some(sk.scalar_eq_parallelized(char.ciphertext(), 0u8)),
                    )
                },
            );

        let mut is_whitespace = sk.boolean_bitor(&is_space, &is_tab);
        sk.boolean_bitor_assign(&mut is_whitespace, &is_new_line);
        sk.boolean_bitor_assign(&mut is_whitespace, &is_form_feed);
        sk.boolean_bitor_assign(&mut is_whitespace, &is_carriage_return);

        if let Some(is_null) = op_is_null {
            sk.boolean_bitor_assign(&mut is_whitespace, &is_null);
        }

        is_whitespace
    }

    fn is_not_whitespace(&self, char: &FheAsciiChar) -> BooleanBlock {
        let sk = self.inner();

        let result = self.is_whitespace(char, false);

        sk.boolean_bitnot(&result)
    }

    fn compare_and_trim<'a, I>(&self, strip_str: I, starts_with_null: bool)
    where
        I: Iterator<Item = &'a mut FheAsciiChar>,
    {
        let sk = self.inner();

        let mut prev_was_ws = sk.create_trivial_boolean_block(true);
        for char in strip_str {
            let mut is_whitespace = self.is_whitespace(char, starts_with_null);
            sk.boolean_bitand_assign(&mut is_whitespace, &prev_was_ws);

            *char.ciphertext_mut() = sk.if_then_else_parallelized(
                &is_whitespace,
                &sk.create_trivial_zero_radix(self.num_ascii_blocks()),
                char.ciphertext(),
            );

            // Once one char isn't (leading / trailing) whitespace, next ones won't be either
            prev_was_ws = is_whitespace;
        }
    }

    /// Returns a new encrypted string with whitespace removed from the start.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "  hello world";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// let result = sk.trim_start(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the start is removed
    /// ```
    pub fn trim_start(&self, str: &FheString) -> FheString {
        let sk = self.inner();

        let mut result = str.clone();

        if str.is_empty() {
            return result;
        }

        self.compare_and_trim(result.chars_mut().iter_mut(), false);

        // Result has potential nulls in the leftmost chars, so we compute the length difference
        // before and after the trimming, and use that amount to shift the result left. This
        // makes the result nulls be at the end
        result.set_is_padded(true);
        if let FheStringLen::Padding(len_after_trim) = self.len(&result) {
            let original_str_len = match self.len(str) {
                FheStringLen::Padding(enc_val) => enc_val,
                FheStringLen::NoPadding(val) => sk.create_trivial_radix(val as u32, 16),
            };

            let shift_left = sk.sub_parallelized(&original_str_len, &len_after_trim);

            result = self.left_shift_chars(&result, &shift_left);
        }

        // If str was not padded originally we don't know if result has nulls at the end or not (we
        // don't know if str was shifted or not) so we ensure it's padded in order to be
        // used in other functions safely
        if str.is_padded() {
            result.set_is_padded(true);
        } else {
            result.append_null(self);
        }

        result
    }

    /// Returns a new encrypted string with whitespace removed from the end.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// let result = sk.trim_end(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the end is removed
    /// ```
    pub fn trim_end(&self, str: &FheString) -> FheString {
        let mut result = str.clone();

        if str.is_empty() {
            return result;
        }

        // If str is padded, when we check for whitespace from the left we have to ignore the nulls
        let include_null = str.is_padded();

        self.compare_and_trim(result.chars_mut().iter_mut().rev(), include_null);

        // If str was originally non-padded, the result is now potentially padded as we may have
        // made the last chars null, so we ensure it's padded in order to be used as input
        // to other functions safely
        if !str.is_padded() {
            result.append_null(self);
        }

        result
    }

    /// Returns a new encrypted string with whitespace removed from both the start and end.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::FheString;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let s = "  hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    ///
    /// let result = sk.trim(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at both ends is removed
    /// ```
    pub fn trim(&self, str: &FheString) -> FheString {
        if str.is_empty() {
            return str.clone();
        }

        let result = self.trim_start(str);
        self.trim_end(&result)
    }
}

/// Creates an iterator over the substrings of this encrypted string, separated by any amount of
/// whitespace.
///
/// Each call to `next` on the iterator returns a tuple with the next encrypted substring and a
/// boolean indicating `Some` (true) or `None` (false) when no more substrings are available.
///
/// When the boolean is `true`, the iterator will yield non-empty encrypted substrings. When the
/// boolean is `false`, the returned encrypted string is always empty.
///
/// # Examples
///
/// ```rust
/// use tfhe::integer::{ClientKey, ServerKey};
/// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// use tfhe::strings::ciphertext::FheString;
/// use tfhe::strings::server_key::{split_ascii_whitespace, FheStringIterator};
///
/// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
/// let sk = ServerKey::new_radix_server_key(&ck);
/// let ck = tfhe::strings::ClientKey::new(ck);
/// let sk = tfhe::strings::ServerKey::new(sk);
/// let s = "hello \t\nworld ";
///
/// let enc_s = FheString::new(&ck, s, None);
///
/// let mut whitespace_iter = split_ascii_whitespace(&enc_s);
/// let (first_item, first_is_some) = whitespace_iter.next(&sk);
/// let (second_item, second_is_some) = whitespace_iter.next(&sk);
/// let (empty, no_more_items) = whitespace_iter.next(&sk); // Attempting to get a third item
///
/// let first_decrypted = ck.decrypt_ascii(&first_item);
/// let first_is_some = ck.inner().decrypt_bool(&first_is_some);
/// let second_decrypted = ck.decrypt_ascii(&second_item);
/// let second_is_some = ck.inner().decrypt_bool(&second_is_some);
/// let empty = ck.decrypt_ascii(&empty);
/// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
///
/// assert_eq!(first_decrypted, "hello");
/// assert!(first_is_some);
/// assert_eq!(second_decrypted, "world");
/// assert!(second_is_some);
/// assert_eq!(empty, ""); // There are no more items so we get an empty string
/// assert!(!no_more_items);
/// ```
pub fn split_ascii_whitespace(str: &FheString) -> SplitAsciiWhitespace {
    let result = str.clone();

    SplitAsciiWhitespace {
        state: result,
        current_mask: None,
    }
}
