use super::contains_cases;
use crate::integer::prelude::*;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey as IntegerServerKey};
use crate::strings::char_iter::CharIter;
use crate::strings::ciphertext::{FheAsciiChar, FheString, GenericPatternRef};
use crate::strings::server_key::pattern::IsMatch;
use crate::strings::server_key::{FheStringIsEmpty, FheStringLen, ServerKey};
use rayon::prelude::*;
use rayon::vec::IntoIter;
use std::borrow::Borrow;

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    // Compare pat with str, with pat shifted right (in relation to str) the number of times given
    // by iter. Returns the first character index of the last match, or the first character index
    // of the first match if the range is reversed. If there's no match defaults to 0
    fn compare_shifted_index(
        &self,
        str_pat: (CharIter, CharIter),
        par_iter: IntoIter<usize>,
        ignore_pat_pad: bool,
    ) -> (RadixCiphertext, BooleanBlock) {
        let sk = self.inner();

        let mut result = sk.create_trivial_boolean_block(false);
        let mut last_match_index = sk.create_trivial_zero_radix(16);
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| {
                let is_matched = if ignore_pat_pad {
                    let str_pat = str.par_iter().skip(start).zip(pat.par_iter());

                    self.asciis_eq_ignore_pat_pad(str_pat)
                } else {
                    self.asciis_eq(str.into_iter().skip(start), pat.into_iter())
                };

                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = sk.create_trivial_radix(i as u32, 16);

            rayon::join(
                || {
                    last_match_index =
                        sk.if_then_else_parallelized(&is_matched, &index, &last_match_index)
                },
                // One of the possible values of the padded pat must match the str
                || sk.boolean_bitor_assign(&mut result, &is_matched),
            );
        }

        (last_match_index, result)
    }

    fn clear_compare_shifted_index(
        &self,
        str_pat: (CharIter, &str),
        par_iter: IntoIter<usize>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let sk = self.inner();

        let mut result = sk.create_trivial_boolean_block(false);
        let mut last_match_index = sk.create_trivial_zero_radix(16);
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| {
                let is_matched = self.clear_asciis_eq(str.into_iter().skip(start), pat);

                (start, is_matched)
            })
            .collect();

        for (i, is_matched) in matched {
            let index = sk.create_trivial_radix(i as u32, 16);

            rayon::join(
                || {
                    last_match_index =
                        sk.if_then_else_parallelized(&is_matched, &index, &last_match_index)
                },
                // One of the possible values of the padded pat must match the str
                || sk.boolean_bitor_assign(&mut result, &is_matched),
            );
        }

        (last_match_index, result)
    }

    /// Returns a tuple containing the byte index of the first character of this encrypted string
    /// that matches the given pattern (either encrypted or clear), and a boolean indicating if a
    /// match was found.
    ///
    /// If the pattern doesn’t match, the function returns a tuple where the boolean part is
    /// `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (haystack, needle) = ("hello world", "world");
    ///
    /// let enc_haystack = FheString::new(&ck, haystack, None);
    /// let enc_needle = GenericPattern::Enc(FheString::new(&ck, needle, None));
    ///
    /// let (index, found) = sk.find(&enc_haystack, enc_needle.as_ref());
    ///
    /// let index = ck.inner().decrypt_radix::<u32>(&index);
    /// let found = ck.inner().decrypt_bool(&found);
    ///
    /// assert!(found);
    /// assert_eq!(index, 6); // "world" starts at index 6 in "hello world"
    /// ```
    pub fn find(
        &self,
        str: &FheString,
        pat: GenericPatternRef<'_>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let sk = self.inner();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        let zero = sk.create_trivial_zero_radix(16);
        match self.length_checks(str, &trivial_or_enc_pat) {
            // bool is true if pattern is empty, in which the first match index is 0. If it's false
            // we default to 0 as well
            IsMatch::Clear(bool) => return (zero, sk.create_trivial_boolean_block(bool)),

            // This variant is only returned in the empty string case so in any case index is 0
            IsMatch::Cipher(val) => return (zero, val),
            IsMatch::None => (),
        }

        let ignore_pat_pad = trivial_or_enc_pat.is_padded();

        let null = (!str.is_padded() && trivial_or_enc_pat.is_padded())
            .then_some(FheAsciiChar::null(self));

        let (str_iter, pat_iter, iter) = contains_cases(str, &trivial_or_enc_pat, null.as_ref());

        let iter_values: Vec<_> = iter.rev().collect();

        match pat {
            GenericPatternRef::Clear(pat) => {
                self.clear_compare_shifted_index((str_iter, pat.str()), iter_values.into_par_iter())
            }
            GenericPatternRef::Enc(_) => self.compare_shifted_index(
                (str_iter, pat_iter),
                iter_values.into_par_iter(),
                ignore_pat_pad,
            ),
        }
    }

    /// Returns a tuple containing the byte index of the first character from the end of this
    /// encrypted string that matches the given pattern (either encrypted or clear), and a
    /// boolean indicating if a match was found.
    ///
    /// If the pattern doesn’t match, the function returns a tuple where the boolean part is
    /// `false`, indicating the equivalent of `None`.
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (haystack, needle) = ("hello world world", "world");
    ///
    /// let enc_haystack = FheString::new(&ck, haystack, None);
    /// let enc_needle = GenericPattern::Enc(FheString::new(&ck, needle, None));
    ///
    /// let (index, found) = sk.rfind(&enc_haystack, enc_needle.as_ref());
    ///
    /// let index = ck.inner().decrypt_radix::<u32>(&index);
    /// let found = ck.inner().decrypt_bool(&found);
    ///
    /// assert!(found);
    /// assert_eq!(index, 12); // The last "world" starts at index 12 in "hello world world"
    /// ```
    pub fn rfind(
        &self,
        str: &FheString,
        pat: GenericPatternRef<'_>,
    ) -> (RadixCiphertext, BooleanBlock) {
        let sk = self.inner();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        let zero = sk.create_trivial_zero_radix(16);
        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => {
                // val = true if pattern is empty, in which the last match index = str.len()
                let index = if val {
                    match self.len(str) {
                        FheStringLen::Padding(cipher_len) => cipher_len,
                        FheStringLen::NoPadding(len) => sk.create_trivial_radix(len as u32, 16),
                    }
                } else {
                    zero
                };

                return (index, sk.create_trivial_boolean_block(val));
            }

            // This variant is only returned in the empty string case so in any case index is 0
            IsMatch::Cipher(val) => return (zero, val),
            IsMatch::None => (),
        }

        let ignore_pat_pad = trivial_or_enc_pat.is_padded();

        let str_len = str.len();
        let (null, ext_iter) = if !str.is_padded() && trivial_or_enc_pat.is_padded() {
            (Some(FheAsciiChar::null(self)), Some(0..str_len + 1))
        } else {
            (None, None)
        };

        let (str_iter, pat_iter, iter) = contains_cases(str, &trivial_or_enc_pat, null.as_ref());

        let iter_values: Vec<_> = ext_iter.unwrap_or(iter).collect();

        let ((mut last_match_index, result), option) = rayon::join(
            || match pat {
                GenericPatternRef::Clear(pat) => self.clear_compare_shifted_index(
                    (str_iter, pat.str()),
                    iter_values.into_par_iter(),
                ),
                GenericPatternRef::Enc(_) => self.compare_shifted_index(
                    (str_iter, pat_iter),
                    iter_values.into_par_iter(),
                    ignore_pat_pad,
                ),
            },
            || {
                // The non padded str case was handled thanks to + 1 in the ext_iter
                if str.is_padded() {
                    let str_true_len = match self.len(str) {
                        FheStringLen::Padding(cipher_len) => cipher_len,
                        FheStringLen::NoPadding(len) => sk.create_trivial_radix(len as u32, 16),
                    };

                    // We have to check if pat is empty as in that case the returned index is
                    // str.len() (the actual length) which doesn't correspond to
                    // our `last_match_index`
                    match self.is_empty(&trivial_or_enc_pat) {
                        FheStringIsEmpty::Padding(is_empty) => Some((is_empty, str_true_len)),
                        FheStringIsEmpty::NoPadding(_) => None,
                    }
                } else {
                    None
                }
            },
        );

        if let Some((pat_is_empty, str_true_len)) = option {
            last_match_index =
                sk.if_then_else_parallelized(&pat_is_empty, &str_true_len, &last_match_index);
        }

        (last_match_index, result)
    }
}
