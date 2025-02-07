use super::{clear_ends_with_cases, ends_with_cases};
use crate::integer::prelude::*;
use crate::integer::{BooleanBlock, ServerKey as IntegerServerKey};
use crate::strings::char_iter::CharIter;
use crate::strings::ciphertext::{FheAsciiChar, FheString, GenericPatternRef};
use crate::strings::server_key::pattern::IsMatch;
use crate::strings::server_key::{FheStringLen, ServerKey};
use rayon::prelude::*;
use std::borrow::Borrow;
use std::ops::Range;

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    fn compare_shifted_strip(
        &self,
        strip_str: &mut FheString,
        str_pat: (CharIter, CharIter),
        iter: Range<usize>,
    ) -> BooleanBlock {
        let sk = self.inner();

        let mut result = sk.create_trivial_boolean_block(false);
        let (str, pat) = str_pat;

        let pat_len = pat.len();
        let str_len = str.len();

        for start in iter {
            let is_matched = self.asciis_eq(str.into_iter().skip(start), pat.into_iter());

            let mut mask = is_matched.clone().into_radix(self.num_ascii_blocks(), sk);

            // If mask == 0u8, it will now be 255u8. If it was 1u8, it will now be 0u8
            sk.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_chars = strip_str.chars_mut().par_iter_mut().skip(start).take(
                if start + pat_len < str_len {
                    pat_len
                } else {
                    str_len
                },
            );

            rayon::join(
                || {
                    mutate_chars.for_each(|char| {
                        sk.bitand_assign_parallelized(char.ciphertext_mut(), &mask);
                    });
                },
                // One of the possible values of pat must match the str
                || sk.boolean_bitor_assign(&mut result, &is_matched),
            );
        }

        result
    }

    fn clear_compare_shifted_strip(
        &self,
        strip_str: &mut FheString,
        str_pat: (CharIter, &str),
        iter: Range<usize>,
    ) -> BooleanBlock {
        let sk = self.inner();

        let mut result = sk.create_trivial_boolean_block(false);
        let (str, pat) = str_pat;

        let pat_len = pat.len();
        let str_len = str.len();
        for start in iter {
            let is_matched = self.clear_asciis_eq(str.into_iter().skip(start), pat);

            let mut mask = is_matched.clone().into_radix(self.num_ascii_blocks(), sk);

            // If mask == 0u8, it will now be 255u8. If it was 1u8, it will now be 0u8
            sk.scalar_sub_assign_parallelized(&mut mask, 1);

            let mutate_chars = strip_str.chars_mut().par_iter_mut().skip(start).take(
                if start + pat_len < str_len {
                    pat_len
                } else {
                    str_len
                },
            );

            rayon::join(
                || {
                    mutate_chars.for_each(|char| {
                        sk.bitand_assign_parallelized(char.ciphertext_mut(), &mask);
                    });
                },
                // One of the possible values of pat must match the str
                || sk.boolean_bitor_assign(&mut result, &is_matched),
            );
        }

        result
    }

    /// Returns a new encrypted string with the specified pattern (either encrypted or clear)
    /// removed from the start of this encrypted string, if it matches. Also returns a boolean
    /// indicating if the pattern was found and removed.
    ///
    /// If the pattern does not match the start of the string, returns the original encrypted
    /// string and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{ClearString, FheString, GenericPattern};
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, prefix, not_prefix) = ("hello world", "hello", "world");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_prefix = GenericPattern::Enc(FheString::new(&ck, prefix, None));
    /// let clear_not_prefix = GenericPattern::Clear(ClearString::new(not_prefix.to_string()));
    ///
    /// let (result, found) = sk.strip_prefix(&enc_s, enc_prefix.as_ref());
    /// let stripped = ck.decrypt_ascii(&result);
    /// let found = ck.inner().decrypt_bool(&found);
    ///
    /// let (result_no_match, not_found) = sk.strip_prefix(&enc_s, clear_not_prefix.as_ref());
    /// let not_stripped = ck.decrypt_ascii(&result_no_match);
    /// let not_found = ck.inner().decrypt_bool(&not_found);
    ///
    /// assert!(found);
    /// assert_eq!(stripped, " world"); // "hello" is stripped from "hello world"
    ///
    /// assert!(!not_found);
    /// assert_eq!(not_stripped, "hello world"); // No match, original string returned
    /// ```
    pub fn strip_prefix(
        &self,
        str: &FheString,
        pat: GenericPatternRef<'_>,
    ) -> (FheString, BooleanBlock) {
        let sk = self.inner();

        let mut result = str.clone();
        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            // If IsMatch is Clear we return the same string (a true means the pattern is empty)
            IsMatch::Clear(bool) => return (result, sk.create_trivial_boolean_block(bool)),

            // If IsMatch is Cipher it means str is empty so in any case we return the same string
            IsMatch::Cipher(val) => return (result, val),
            IsMatch::None => (),
        }

        let (starts_with, real_pat_len) = rayon::join(
            || self.starts_with(str, pat),
            || match self.len(&trivial_or_enc_pat) {
                FheStringLen::Padding(enc_val) => enc_val,
                FheStringLen::NoPadding(val) => sk.create_trivial_radix(val as u32, 16),
            },
        );

        // If there's match we shift the str left by `real_pat_len` (removing the prefix and adding
        // nulls at the end), else we shift it left by 0
        let shift_left = sk.if_then_else_parallelized(
            &starts_with,
            &real_pat_len,
            &sk.create_trivial_zero_radix(16),
        );

        result = self.left_shift_chars(str, &shift_left);

        // If str was not padded originally we don't know if result has nulls at the end or not (we
        // don't know if str was shifted or not) so we ensure it's padded in order to be
        // used in other functions safely
        if str.is_padded() {
            result.set_is_padded(true);
        } else {
            result.append_null(self);
        }

        (result, starts_with)
    }

    /// Returns a new encrypted string with the specified pattern (either encrypted or clear)
    /// removed from the end of this encrypted string, if it matches. Also returns a boolean
    /// indicating if the pattern was found and removed.
    ///
    /// If the pattern does not match the end of the string, returns the original encrypted string
    /// and a boolean set to `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{ClearString, FheString, GenericPattern};
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, suffix, not_suffix) = ("hello world", "world", "hello");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_suffix = GenericPattern::Enc(FheString::new(&ck, suffix, None));
    /// let clear_not_suffix = GenericPattern::Clear(ClearString::new(not_suffix.to_string()));
    ///
    /// let (result, found) = sk.strip_suffix(&enc_s, enc_suffix.as_ref());
    /// let stripped = ck.decrypt_ascii(&result);
    /// let found = ck.inner().decrypt_bool(&found);
    ///
    /// let (result_no_match, not_found) = sk.strip_suffix(&enc_s, clear_not_suffix.as_ref());
    /// let not_stripped = ck.decrypt_ascii(&result_no_match);
    /// let not_found = ck.inner().decrypt_bool(&not_found);
    ///
    /// assert!(found);
    /// assert_eq!(stripped, "hello "); // "world" is stripped from "hello world"
    ///
    /// assert!(!not_found);
    /// assert_eq!(not_stripped, "hello world"); // No match, original string returned
    /// ```
    pub fn strip_suffix(
        &self,
        str: &FheString,
        pat: GenericPatternRef<'_>,
    ) -> (FheString, BooleanBlock) {
        let sk = self.inner();

        let mut result = str.clone();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            // If IsMatch is Clear we return the same string (a true means the pattern is empty)
            IsMatch::Clear(bool) => return (result, sk.create_trivial_boolean_block(bool)),

            // If IsMatch is Cipher it means str is empty so in any case we return the same string
            IsMatch::Cipher(val) => return (result, val),
            IsMatch::None => (),
        }

        let is_match = match pat {
            GenericPatternRef::Clear(pat) => {
                let (str_iter, clear_pat, iter) = clear_ends_with_cases(str, pat.str());

                self.clear_compare_shifted_strip(&mut result, (str_iter, &clear_pat), iter)
            }
            GenericPatternRef::Enc(pat) => {
                let null = (str.is_padded() ^ pat.is_padded()).then_some(FheAsciiChar::null(self));

                let (str_iter, pat_iter, iter) = ends_with_cases(str, pat, null.as_ref());

                self.compare_shifted_strip(&mut result, (str_iter, pat_iter), iter)
            }
        };

        // If str was originally non padded, the result is now potentially padded as we may have
        // made the last chars null, so we ensure it's padded in order to be used as input
        // to other functions safely
        if !str.is_padded() {
            result.append_null(self);
        }

        (result, is_match)
    }
}
