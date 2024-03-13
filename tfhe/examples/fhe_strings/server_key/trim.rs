use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{FheStringIsEmpty, FheStringIterator, FheStringLen, ServerKey};
use rayon::prelude::*;
use tfhe::integer::BooleanBlock;

pub struct SplitAsciiWhitespace {
    state: FheString,
    current_mask: Option<FheString>,
}

impl FheStringIterator for SplitAsciiWhitespace {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let str_len = self.state.chars().len();

        if str_len == 0 || (self.state.is_padded() && str_len == 1) {
            return (
                FheString::empty(),
                sk.key.create_trivial_boolean_block(false),
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
                    sk.key.boolean_bitnot(&val)
                } else {
                    panic!("Empty str case was handled so 'state_after_trim' is padded")
                }
            },
        )
    }
}

impl SplitAsciiWhitespace {
    // The mask contains 255u8 until we find some whitespace, then will be 0u8
    fn create_and_apply_mask(&mut self, sk: &ServerKey) -> FheString {
        let mut mask = self.state.clone();
        let mut result = self.state.clone();

        let mut prev_was_not = sk.key.create_trivial_boolean_block(true);
        for char in mask.chars_mut().iter_mut() {
            let mut is_not_ws = sk.is_not_whitespace(char);
            sk.key.boolean_bitand_assign(&mut is_not_ws, &prev_was_not);

            let mut mask_u8 = is_not_ws.clone().into_radix(4, &sk.key);

            // 0u8 is kept the same, but 1u8 is transformed into 255u8
            sk.key.scalar_sub_assign_parallelized(&mut mask_u8, 1);
            sk.key.bitnot_assign(&mut mask_u8);

            *char.ciphertext_mut() = mask_u8;

            prev_was_not = is_not_ws;
        }

        // Apply the mask to get the result
        result
            .chars_mut()
            .iter_mut()
            .zip(mask.chars())
            .par_bridge()
            .for_each(|(char, mask_u8)| {
                sk.key
                    .bitand_assign_parallelized(char.ciphertext_mut(), mask_u8.ciphertext());
            });

        self.current_mask = Some(mask);

        result
    }

    // Shifts the string left to get the remaining string (starting at the next first whitespace)
    fn remaining_string(&mut self, sk: &ServerKey) {
        let mask = self.current_mask.as_ref().unwrap();

        let mut number_of_trues = sk.key.create_trivial_zero_radix(16);
        for mask_u8 in mask.chars() {
            let is_true = sk.key.scalar_eq_parallelized(mask_u8.ciphertext(), 255u8);
            sk.key
                .add_assign_parallelized(&mut number_of_trues, &is_true.into_radix(1, &sk.key));
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

impl ServerKey {
    // As specified in https://doc.rust-lang.org/core/primitive.char.html#method.is_ascii_whitespace
    fn is_whitespace(&self, char: &FheAsciiChar, or_null: bool) -> BooleanBlock {
        let (((is_space, is_tab), (is_new_line, is_form_feed)), (is_carriage_return, op_is_null)) =
            rayon::join(
                || {
                    rayon::join(
                        || {
                            rayon::join(
                                || self.key.scalar_eq_parallelized(char.ciphertext(), 0x20u8),
                                || self.key.scalar_eq_parallelized(char.ciphertext(), 0x09u8),
                            )
                        },
                        || {
                            rayon::join(
                                || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Au8),
                                || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Cu8),
                            )
                        },
                    )
                },
                || {
                    rayon::join(
                        || self.key.scalar_eq_parallelized(char.ciphertext(), 0x0Du8),
                        || {
                            or_null
                                .then_some(self.key.scalar_eq_parallelized(char.ciphertext(), 0u8))
                        },
                    )
                },
            );

        let mut is_whitespace = self.key.boolean_bitor(&is_space, &is_tab);
        self.key
            .boolean_bitor_assign(&mut is_whitespace, &is_new_line);
        self.key
            .boolean_bitor_assign(&mut is_whitespace, &is_form_feed);
        self.key
            .boolean_bitor_assign(&mut is_whitespace, &is_carriage_return);

        if let Some(is_null) = op_is_null {
            self.key.boolean_bitor_assign(&mut is_whitespace, &is_null);
        }

        is_whitespace
    }

    fn is_not_whitespace(&self, char: &FheAsciiChar) -> BooleanBlock {
        let result = self.is_whitespace(char, false);

        self.key.boolean_bitnot(&result)
    }

    fn compare_and_trim<'a, I>(&self, strip_str: I, starts_with_null: bool)
    where
        I: Iterator<Item = &'a mut FheAsciiChar>,
    {
        let mut prev_was_ws = self.key.create_trivial_boolean_block(true);
        for char in strip_str {
            let mut is_whitespace = self.is_whitespace(char, starts_with_null);
            self.key
                .boolean_bitand_assign(&mut is_whitespace, &prev_was_ws);

            *char.ciphertext_mut() = self.key.if_then_else_parallelized(
                &is_whitespace,
                &self.key.create_trivial_zero_radix(4),
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
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let s = "  hello world";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim_start(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the start is removed
    /// ```
    pub fn trim_start(&self, str: &FheString) -> FheString {
        let mut result = str.clone();

        if str.chars().is_empty() || (str.is_padded() && str.chars().len() == 1) {
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
                FheStringLen::NoPadding(val) => self.key.create_trivial_radix(val as u32, 16),
            };

            let shift_left = self
                .key
                .sub_parallelized(&original_str_len, &len_after_trim);

            result = self.left_shift_chars(&result, &shift_left);
        }

        // If str was not padded originally we don't know if result has nulls at the end or not (we
        // don't know if str was shifted or not) so we ensure it's padded in order to be
        // used in other functions safely
        if !str.is_padded() {
            result.append_null(self);
        } else {
            result.set_is_padded(true);
        }

        result
    }

    /// Returns a new encrypted string with whitespace removed from the end.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let s = "hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim_end(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at the end is removed
    /// ```
    pub fn trim_end(&self, str: &FheString) -> FheString {
        let mut result = str.clone();

        if str.chars().is_empty() || (str.is_padded() && str.chars().len() == 1) {
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
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let s = "  hello world  ";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let result = sk.trim(&enc_s);
    /// let trimmed = ck.decrypt_ascii(&result);
    ///
    /// assert_eq!(trimmed, "hello world"); // Whitespace at both ends is removed
    /// ```
    pub fn trim(&self, str: &FheString) -> FheString {
        if str.chars().is_empty() || (str.is_padded() && str.chars().len() == 1) {
            return str.clone();
        }

        let result = self.trim_start(str);
        self.trim_end(&result)
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
    /// use crate::ciphertext::FheString;
    /// use crate::server_key::{gen_keys, FheStringIterator};
    ///
    /// let (ck, sk) = gen_keys();
    /// let s = "hello \t\nworld ";
    ///
    /// let enc_s = FheString::new(&ck, &s, None);
    ///
    /// let mut whitespace_iter = sk.split_ascii_whitespace(&enc_s);
    /// let (first_item, first_is_some) = whitespace_iter.next(&sk);
    /// let (second_item, second_is_some) = whitespace_iter.next(&sk);
    /// let (empty, no_more_items) = whitespace_iter.next(&sk); // Attempting to get a third item
    ///
    /// let first_decrypted = ck.decrypt_ascii(&first_item);
    /// let first_is_some = ck.key().decrypt_bool(&first_is_some);
    /// let second_decrypted = ck.decrypt_ascii(&second_item);
    /// let second_is_some = ck.key().decrypt_bool(&second_is_some);
    /// let empty = ck.decrypt_ascii(&empty);
    /// let no_more_items = ck.key().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(first_decrypted, "hello");
    /// assert!(first_is_some);
    /// assert_eq!(second_decrypted, "world");
    /// assert!(second_is_some);
    /// assert_eq!(empty, ""); // There are no more items so we get an empty string
    /// assert!(!no_more_items);
    /// ```
    pub fn split_ascii_whitespace(&self, str: &FheString) -> SplitAsciiWhitespace {
        let result = str.clone();

        SplitAsciiWhitespace {
            state: result,
            current_mask: None,
        }
    }
}
