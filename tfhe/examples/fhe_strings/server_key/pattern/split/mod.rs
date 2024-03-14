mod split_iters;

use crate::ciphertext::{FheString, GenericPattern, UIntArg};
use crate::server_key::pattern::IsMatch;
use crate::server_key::{FheStringIsEmpty, FheStringIterator, FheStringLen, ServerKey};
use tfhe::integer::{BooleanBlock, RadixCiphertext};

impl ServerKey {
    fn split_pat_at_index(
        &self,
        str: &FheString,
        pat: &GenericPattern,
        index: &RadixCiphertext,
        inclusive: bool,
    ) -> (FheString, FheString) {
        let str_len = self.key.create_trivial_radix(str.chars().len() as u32, 16);
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        let (mut shift_right, real_pat_len) = rayon::join(
            || self.key.sub_parallelized(&str_len, index),
            || match self.len(&trivial_or_enc_pat) {
                FheStringLen::Padding(enc_val) => enc_val,
                FheStringLen::NoPadding(val) => self.key.create_trivial_radix(val as u32, 16),
            },
        );

        let (mut lhs, mut rhs) = rayon::join(
            || {
                if inclusive {
                    // Remove the real pattern length from the amount to shift
                    self.key
                        .sub_assign_parallelized(&mut shift_right, &real_pat_len);
                }

                let lhs = self.right_shift_chars(str, &shift_right);

                // lhs potentially has nulls in the leftmost chars as we have shifted str right, so
                // we move back the nulls to the end by performing the reverse shift
                self.left_shift_chars(&lhs, &shift_right)
            },
            || {
                let shift_left = self.key.add_parallelized(&real_pat_len, index);

                self.left_shift_chars(str, &shift_left)
            },
        );

        // If original str is padded we set both sub strings padded as well. If str was not padded,
        // then we don't know if a sub string is padded or not, so we add a null to both
        // because we cannot assume one isn't padded
        if str.is_padded() {
            lhs.set_is_padded(true);
            rhs.set_is_padded(true);
        } else {
            lhs.append_null(self);
            rhs.append_null(self);
        }

        (lhs, rhs)
    }

    /// Splits the encrypted string into two substrings at the last occurrence of the pattern
    /// (either encrypted or clear) and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// If the pattern is not found returns `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s, pat) = (" hello world", " ");
    /// let enc_s = FheString::new(&ck, &s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, &pat, None));
    ///
    /// let (lhs, rhs, split_occurred) = sk.rsplit_once(&enc_s, &enc_pat);
    ///
    /// let lhs_decrypted = ck.decrypt_ascii(&lhs);
    /// let rhs_decrypted = ck.decrypt_ascii(&rhs);
    /// let split_occurred = ck.key().decrypt_bool(&split_occurred);
    ///
    /// assert_eq!(lhs_decrypted, " hello");
    /// assert_eq!(rhs_decrypted, "world");
    /// assert!(split_occurred);
    /// ```
    pub fn rsplit_once(
        &self,
        str: &FheString,
        pat: &GenericPattern,
    ) -> (FheString, FheString, BooleanBlock) {
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => {
                return if val {
                    // `val` is set only when the pattern is empty, so the last match is at the end
                    (
                        str.clone(),
                        FheString::empty(),
                        self.key.create_trivial_boolean_block(true),
                    )
                } else {
                    // There's no match so we default to empty string and str
                    (
                        FheString::empty(),
                        str.clone(),
                        self.key.create_trivial_boolean_block(false),
                    )
                };
            }
            // This is only returned when str is empty so both sub-strings are empty as well
            IsMatch::Cipher(enc_val) => return (FheString::empty(), FheString::empty(), enc_val),
            _ => (),
        }

        let (index, is_match) = self.rfind(str, pat);

        let (lhs, rhs) = self.split_pat_at_index(str, pat, &index, false);

        (lhs, rhs, is_match)
    }

    /// Splits the encrypted string into two substrings at the first occurrence of the pattern
    /// (either encrypted or clear) and returns a tuple of the two substrings along with a boolean
    /// indicating if the split occurred.
    ///
    /// If the pattern is not found returns `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (s, pat) = (" hello world", " ");
    /// let enc_s = FheString::new(&ck, &s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, &pat, None));
    ///
    /// let (lhs, rhs, split_occurred) = sk.split_once(&enc_s, &enc_pat);
    ///
    /// let lhs_decrypted = ck.decrypt_ascii(&lhs);
    /// let rhs_decrypted = ck.decrypt_ascii(&rhs);
    /// let split_occurred = ck.key().decrypt_bool(&split_occurred);
    ///
    /// assert_eq!(lhs_decrypted, "");
    /// assert_eq!(rhs_decrypted, "hello world");
    /// assert!(split_occurred);
    /// ```
    pub fn split_once(
        &self,
        str: &FheString,
        pat: &GenericPattern,
    ) -> (FheString, FheString, BooleanBlock) {
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => {
                return if val {
                    // `val` is set only when the pattern is empty, so the first match is index 0
                    (
                        FheString::empty(),
                        str.clone(),
                        self.key.create_trivial_boolean_block(true),
                    )
                } else {
                    // There's no match so we default to empty string and str
                    (
                        FheString::empty(),
                        str.clone(),
                        self.key.create_trivial_boolean_block(false),
                    )
                };
            }
            // This is only returned when str is empty so both sub-strings are empty as well
            IsMatch::Cipher(enc_val) => return (FheString::empty(), FheString::empty(), enc_val),
            _ => (),
        }

        let (index, is_match) = self.find(str, pat);

        let (lhs, rhs) = self.split_pat_at_index(str, pat, &index, false);

        (lhs, rhs, is_match)
    }

    fn split_internal(
        &self,
        str: &FheString,
        pat: &GenericPattern,
        split_type: SplitType,
    ) -> SplitInternal {
        let mut max_counter = match self.len(str) {
            FheStringLen::Padding(enc_val) => enc_val,
            FheStringLen::NoPadding(val) => self.key.create_trivial_radix(val as u32, 16),
        };

        self.key.scalar_add_assign_parallelized(&mut max_counter, 1);

        SplitInternal {
            split_type,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_boolean_block(true),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_boolean_block(true),
        }
    }

    fn splitn_internal(
        &self,
        str: &FheString,
        pat: &GenericPattern,
        n: UIntArg,
        split_type: SplitType,
    ) -> SplitNInternal {
        if let SplitType::SplitInclusive = split_type {
            panic!("We have either SplitN or RSplitN")
        }

        let uint_not_0 = match &n {
            UIntArg::Clear(val) => {
                if *val != 0 {
                    self.key.create_trivial_boolean_block(true)
                } else {
                    self.key.create_trivial_boolean_block(false)
                }
            }
            UIntArg::Enc(enc) => self.key.scalar_ne_parallelized(enc.cipher(), 0),
        };

        let internal = self.split_internal(str, pat, split_type);

        SplitNInternal {
            internal,
            n,
            counter: 0,
            not_exceeded: uint_not_0,
        }
    }

    fn split_no_trailing(
        &self,
        str: &FheString,
        pat: &GenericPattern,
        split_type: SplitType,
    ) -> SplitNoTrailing {
        if let SplitType::RSplit = split_type {
            panic!("Only Split or SplitInclusive")
        }

        let max_counter = match self.len(str) {
            FheStringLen::Padding(enc_val) => enc_val,
            FheStringLen::NoPadding(val) => self.key.create_trivial_radix(val as u32, 16),
        };

        let internal = SplitInternal {
            split_type,
            state: str.clone(),
            pat: pat.clone(),
            prev_was_some: self.key.create_trivial_boolean_block(true),
            counter: 0,
            max_counter,
            counter_lt_max: self.key.create_trivial_boolean_block(true),
        };

        SplitNoTrailing { internal }
    }

    fn split_no_leading(&self, str: &FheString, pat: &GenericPattern) -> SplitNoLeading {
        let mut internal = self.split_internal(str, pat, SplitType::RSplit);

        let prev_return = internal.next(self);

        let leading_empty_str = match self.is_empty(&prev_return.0) {
            FheStringIsEmpty::Padding(enc) => enc,
            FheStringIsEmpty::NoPadding(clear) => self.key.create_trivial_boolean_block(clear),
        };

        SplitNoLeading {
            internal,
            prev_return,
            leading_empty_str,
        }
    }
}

enum SplitType {
    Split,
    RSplit,
    SplitInclusive,
}

struct SplitInternal {
    split_type: SplitType,
    state: FheString,
    pat: GenericPattern,
    prev_was_some: BooleanBlock,
    counter: u16,
    max_counter: RadixCiphertext,
    counter_lt_max: BooleanBlock,
}

struct SplitNInternal {
    internal: SplitInternal,
    n: UIntArg,
    counter: u16,
    not_exceeded: BooleanBlock,
}

struct SplitNoTrailing {
    internal: SplitInternal,
}

struct SplitNoLeading {
    internal: SplitInternal,
    prev_return: (FheString, BooleanBlock),
    leading_empty_str: BooleanBlock,
}

impl FheStringIterator for SplitInternal {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let trivial_or_enc_pat = match &self.pat {
            GenericPattern::Clear(pat) => FheString::trivial(sk, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        let ((mut index, mut is_some), pat_is_empty) = rayon::join(
            || {
                if let SplitType::RSplit = self.split_type {
                    sk.rfind(&self.state, &self.pat)
                } else {
                    sk.find(&self.state, &self.pat)
                }
            },
            || match sk.is_empty(&trivial_or_enc_pat) {
                FheStringIsEmpty::Padding(enc) => enc.into_radix(16, &sk.key),
                FheStringIsEmpty::NoPadding(clear) => sk.key.create_trivial_radix(clear as u32, 16),
            },
        );

        if self.counter > 0 {
            // If pattern is empty and we aren't in the first next call, we add (in the Split case)
            // or subtract (in the RSplit case) 1 to the index at which we split the str.
            //
            // This is because "ab".split("") returns ["", "a", "b", ""] and, in our case, we have
            // to manually advance the match index as an empty pattern always matches at the very
            // start (or end in the rsplit case)

            if let SplitType::RSplit = self.split_type {
                sk.key.sub_assign_parallelized(&mut index, &pat_is_empty);
            } else {
                sk.key.add_assign_parallelized(&mut index, &pat_is_empty);
            }
        }

        let (lhs, rhs) = if let SplitType::SplitInclusive = self.split_type {
            sk.split_pat_at_index(&self.state, &self.pat, &index, true)
        } else {
            sk.split_pat_at_index(&self.state, &self.pat, &index, false)
        };

        let current_is_some = is_some.clone();

        // The moment it's None (no match) we return the remaining state
        let result = if let SplitType::RSplit = self.split_type {
            let re = sk.conditional_string(&current_is_some, rhs, &self.state);

            self.state = lhs;
            re
        } else {
            let re = sk.conditional_string(&current_is_some, lhs, &self.state);

            self.state = rhs;
            re
        };

        // Even if there isn't match, we return Some if there was match in the previous next call,
        // as we are returning the remaining state "wrapped" in Some
        sk.key
            .boolean_bitor_assign(&mut is_some, &self.prev_was_some);

        // If pattern is empty, `is_some` is always true, so we make it false when we have reached
        // the last possible counter value
        sk.key
            .boolean_bitand_assign(&mut is_some, &self.counter_lt_max);

        self.prev_was_some = current_is_some;
        self.counter_lt_max = sk
            .key
            .scalar_gt_parallelized(&self.max_counter, self.counter);

        self.counter += 1;

        (result, is_some)
    }
}

impl FheStringIterator for SplitNInternal {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let state = self.internal.state.clone();

        let (mut result, mut is_some) = self.internal.next(sk);

        // This keeps the original `is_some` value unless we have exceeded n
        sk.key
            .boolean_bitand_assign(&mut is_some, &self.not_exceeded);

        // The moment counter is at least one less than n we return the remaining state, and make
        // `not_exceeded` false such that next calls are always None
        match &self.n {
            UIntArg::Clear(clear_n) => {
                if self.counter >= clear_n - 1 {
                    result = state;
                    self.not_exceeded = sk.key.create_trivial_boolean_block(false);
                }
            }
            UIntArg::Enc(enc_n) => {
                // Note that when `enc_n` is zero `n_minus_one` wraps to a very large number and so
                // `exceeded` will be false. Nonetheless the initial value of `not_exceeded`
                // was set to false in the n is zero case, so we return None
                let n_minus_one = sk.key.scalar_sub_parallelized(enc_n.cipher(), 1);
                let exceeded = sk.key.scalar_le_parallelized(&n_minus_one, self.counter);

                rayon::join(
                    || result = sk.conditional_string(&exceeded, state, &result),
                    || {
                        let current_not_exceeded = sk.key.boolean_bitnot(&exceeded);

                        // If current is not exceeded we use the previous not_exceeded value,
                        // or false if it's exceeded
                        sk.key
                            .boolean_bitand_assign(&mut self.not_exceeded, &current_not_exceeded);
                    },
                );
            }
        }

        self.counter += 1;

        (result, is_some)
    }
}

impl FheStringIterator for SplitNoTrailing {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        let (result, mut is_some) = self.internal.next(sk);

        let (result_is_empty, prev_was_none) = rayon::join(
            // It's possible that the returned value is Some but it's wrapping the remaining state
            // (if prev_was_some is false). If this is the case and we have a trailing empty
            // string, we return None to remove it
            || match sk.is_empty(&result) {
                FheStringIsEmpty::Padding(enc) => enc,
                FheStringIsEmpty::NoPadding(clear) => sk.key.create_trivial_boolean_block(clear),
            },
            || sk.key.boolean_bitnot(&self.internal.prev_was_some),
        );

        let trailing_empty_str = sk.key.boolean_bitand(&result_is_empty, &prev_was_none);

        let not_trailing_empty_str = sk.key.boolean_bitnot(&trailing_empty_str);

        // If there's no empty trailing string we get the previous `is_some`,
        // else we get false (None)
        sk.key
            .boolean_bitand_assign(&mut is_some, &not_trailing_empty_str);

        (result, is_some)
    }
}

impl FheStringIterator for SplitNoLeading {
    fn next(&mut self, sk: &ServerKey) -> (FheString, BooleanBlock) {
        // We want to remove the leading empty string i.e. the first returned substring should be
        // skipped if empty.
        //
        // To achieve that we have computed a next call in advance and conditionally assign values
        // based on the `trailing_empty_str` flag

        let (result, is_some) = self.internal.next(sk);

        let (return_result, return_is_some) = rayon::join(
            || sk.conditional_string(&self.leading_empty_str, result.clone(), &self.prev_return.0),
            || {
                let (lhs, rhs) = rayon::join(
                    // This is `is_some` if `leading_empty_str` is true, false otherwise
                    || sk.key.boolean_bitand(&self.leading_empty_str, &is_some),
                    // This is the flag from the previous next call if `leading_empty_str` is true,
                    // false otherwise
                    || {
                        sk.key.boolean_bitand(
                            &sk.key.boolean_bitnot(&self.leading_empty_str),
                            &self.prev_return.1,
                        )
                    },
                );

                sk.key.boolean_bitor(&lhs, &rhs)
            },
        );

        self.prev_return = (result, is_some);

        (return_result, return_is_some)
    }
}
