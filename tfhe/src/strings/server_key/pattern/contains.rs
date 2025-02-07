use super::{clear_ends_with_cases, contains_cases, ends_with_cases};
use crate::integer::{
    BooleanBlock, IntegerRadixCiphertext, RadixCiphertext, ServerKey as IntegerServerKey,
};
use crate::strings::char_iter::CharIter;
use crate::strings::ciphertext::{FheAsciiChar, FheString, GenericPatternRef};
use crate::strings::server_key::pattern::IsMatch;
use crate::strings::server_key::ServerKey;
use itertools::Itertools;
use rayon::prelude::*;
use rayon::range::Iter;
use std::borrow::Borrow;

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    // Compare pat with str, with pat shifted right (in relation to str) the number given by iter
    fn compare_shifted(
        &self,
        str_pat: (CharIter, CharIter),
        par_iter: Iter<usize>,
        ignore_pat_pad: bool,
    ) -> BooleanBlock {
        let sk = self.inner();

        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| {
                if ignore_pat_pad {
                    let str_chars = str.par_iter().skip(start).zip(pat.par_iter());

                    self.asciis_eq_ignore_pat_pad(str_chars)
                } else {
                    self.asciis_eq(str.into_iter().skip(start), pat.into_iter())
                }
            })
            .collect();

        let block_vec: Vec<_> = matched
            .into_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, sk);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);

        sk.scalar_ne_parallelized(&combined_radix, 0)
    }

    fn clear_compare_shifted(
        &self,
        str_pat: (CharIter, &str),
        par_iter: Iter<usize>,
    ) -> BooleanBlock {
        let sk = self.inner();

        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| self.clear_asciis_eq(str.into_iter().skip(start), pat))
            .collect();

        let block_vec: Vec<_> = matched
            .into_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, sk);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);

        sk.scalar_ne_parallelized(&combined_radix, 0)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a substring of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match any substring.
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
    /// let (bananas, nana, apples) = ("bananas", "nana", "apples");
    ///
    /// let enc_bananas = FheString::new(&ck, bananas, None);
    /// let enc_nana = GenericPattern::Enc(FheString::new(&ck, nana, None));
    /// let clear_apples = GenericPattern::Clear(ClearString::new(apples.to_string()));
    ///
    /// let result1 = sk.contains(&enc_bananas, enc_nana.as_ref());
    /// let result2 = sk.contains(&enc_bananas, clear_apples.as_ref());
    ///
    /// let should_be_true = ck.inner().decrypt_bool(&result1);
    /// let should_be_false = ck.inner().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn contains(&self, str: &FheString, pat: GenericPatternRef<'_>) -> BooleanBlock {
        let sk = self.inner();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return sk.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            IsMatch::None => (),
        }

        let ignore_pat_pad = trivial_or_enc_pat.is_padded();

        let null = (!str.is_padded() && trivial_or_enc_pat.is_padded())
            .then_some(FheAsciiChar::null(self));

        let (str_iter, pat_iter, iter) = contains_cases(str, &trivial_or_enc_pat, null.as_ref());

        match pat {
            GenericPatternRef::Clear(pat) => {
                self.clear_compare_shifted((str_iter, pat.str()), iter.into_par_iter())
            }
            GenericPatternRef::Enc(_) => {
                self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), ignore_pat_pad)
            }
        }
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a prefix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the prefix.
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
    /// let (bananas, ba, nan) = ("bananas", "ba", "nan");
    ///
    /// let enc_bananas = FheString::new(&ck, bananas, None);
    /// let enc_ba = GenericPattern::Enc(FheString::new(&ck, ba, None));
    /// let clear_nan = GenericPattern::Clear(ClearString::new(nan.to_string()));
    ///
    /// let result1 = sk.starts_with(&enc_bananas, enc_ba.as_ref());
    /// let result2 = sk.starts_with(&enc_bananas, clear_nan.as_ref());
    ///
    /// let should_be_true = ck.inner().decrypt_bool(&result1);
    /// let should_be_false = ck.inner().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn starts_with(&self, str: &FheString, pat: GenericPatternRef<'_>) -> BooleanBlock {
        let sk = self.inner();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return sk.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            IsMatch::None => (),
        }

        if !trivial_or_enc_pat.is_padded() {
            return match pat {
                GenericPatternRef::Clear(pat) => {
                    self.clear_asciis_eq(str.chars().iter(), pat.str())
                }
                GenericPatternRef::Enc(pat) => {
                    self.asciis_eq(str.chars().iter(), pat.chars().iter())
                }
            };
        }

        let str_len = str.len();
        let pat_len = trivial_or_enc_pat.len();

        // In the padded pattern case we can remove the last char (as it's always null)
        let pat_chars = &trivial_or_enc_pat.chars()[..pat_len - 1];

        let null = FheAsciiChar::null(self);
        let str_chars = if !str.is_padded() && (str_len < pat_len - 1) {
            // If str = "xy" and pat = "xyz\0", then str[..] == pat[..2], but instead we have
            // to check if "xy\0" == pat[..3] (i.e. check that the actual pattern isn't longer)
            str.chars()
                .iter()
                .chain(std::iter::once(&null))
                .collect_vec()
        } else {
            str.chars().iter().collect_vec()
        };

        let str_pat = str_chars.par_iter().copied().zip(pat_chars.par_iter());

        self.asciis_eq_ignore_pat_pad(str_pat)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a suffix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the suffix.
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
    /// let (bananas, anas, nana) = ("bananas", "anas", "nana");
    ///
    /// let enc_bananas = FheString::new(&ck, bananas, None);
    /// let enc_anas = GenericPattern::Enc(FheString::new(&ck, anas, None));
    /// let clear_nana = GenericPattern::Clear(ClearString::new(nana.to_string()));
    ///
    /// let result1 = sk.ends_with(&enc_bananas, enc_anas.as_ref());
    /// let result2 = sk.ends_with(&enc_bananas, clear_nana.as_ref());
    ///
    /// let should_be_true = ck.inner().decrypt_bool(&result1);
    /// let should_be_false = ck.inner().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn ends_with(&self, str: &FheString, pat: GenericPatternRef<'_>) -> BooleanBlock {
        let sk = self.inner();

        let trivial_or_enc_pat = match pat {
            GenericPatternRef::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPatternRef::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return sk.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            IsMatch::None => (),
        }

        match pat {
            GenericPatternRef::Clear(pat) => {
                let (str_iter, clear_pat, iter) = clear_ends_with_cases(str, pat.str());

                self.clear_compare_shifted((str_iter, &clear_pat), iter.into_par_iter())
            }
            GenericPatternRef::Enc(pat) => {
                let null = (str.is_padded() ^ pat.is_padded()).then_some(FheAsciiChar::null(self));

                let (str_iter, pat_iter, iter) = ends_with_cases(str, pat, null.as_ref());

                self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), false)
            }
        }
    }
}
