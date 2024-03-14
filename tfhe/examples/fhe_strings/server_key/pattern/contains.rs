use crate::ciphertext::{FheAsciiChar, FheString, GenericPattern};
use crate::server_key::pattern::{CharIter, IsMatch};
use crate::server_key::ServerKey;
use rayon::prelude::*;
use rayon::range::Iter;
use tfhe::integer::{BooleanBlock, IntegerRadixCiphertext, RadixCiphertext};

impl ServerKey {
    // Compare pat with str, with pat shifted right (in relation to str) the number given by iter
    fn compare_shifted(
        &self,
        str_pat: (CharIter, CharIter),
        par_iter: Iter<usize>,
        ignore_pat_pad: bool,
    ) -> BooleanBlock {
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| {
                let str_chars = str.clone().skip(start);
                let pat_chars = pat.clone();

                if ignore_pat_pad {
                    let str_pat = str_chars.into_iter().zip(pat_chars).par_bridge();

                    self.asciis_eq_ignore_pat_pad(str_pat)
                } else {
                    let a: Vec<&FheAsciiChar> = str_chars.collect();
                    let b: Vec<&FheAsciiChar> = pat_chars.collect();

                    self.asciis_eq(a.into_iter(), b.into_iter())
                }
            })
            .collect();

        let block_vec: Vec<_> = matched
            .into_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, &self.key);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);

        self.key.scalar_ne_parallelized(&combined_radix, 0)
    }

    fn clear_compare_shifted(
        &self,
        str_pat: (CharIter, &str),
        par_iter: Iter<usize>,
    ) -> BooleanBlock {
        let (str, pat) = str_pat;

        let matched: Vec<_> = par_iter
            .map(|start| {
                let str_chars = str.clone().skip(start);
                let a: Vec<&FheAsciiChar> = str_chars.collect();

                self.clear_asciis_eq(a.into_iter(), pat)
            })
            .collect();

        let block_vec: Vec<_> = matched
            .into_iter()
            .map(|bool| {
                let radix: RadixCiphertext = bool.into_radix(1, &self.key);
                radix.into_blocks()[0].clone()
            })
            .collect();

        // This will be 0 if there was no match, non-zero otherwise
        let combined_radix = RadixCiphertext::from(block_vec);

        self.key.scalar_ne_parallelized(&combined_radix, 0)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a substring of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match any substring.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{ClearString, FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (bananas, nana, apples) = ("bananas", "nana", "apples");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_nana = GenericPattern::Enc(FheString::new(&ck, &nana, None));
    /// let clear_apples = GenericPattern::Clear(ClearString::new(apples.to_string()));
    ///
    /// let result1 = sk.contains(&enc_bananas, &enc_nana);
    /// let result2 = sk.contains(&enc_bananas, &clear_apples);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn contains(&self, str: &FheString, pat: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        let ignore_pat_pad = trivial_or_enc_pat.is_padded();

        let null = (!str.is_padded() && trivial_or_enc_pat.is_padded())
            .then_some(FheAsciiChar::null(self));

        let (str_iter, pat_iter, iter) =
            self.contains_cases(str, &trivial_or_enc_pat, null.as_ref());

        match pat {
            GenericPattern::Clear(pat) => {
                self.clear_compare_shifted((str_iter, pat.str()), iter.into_par_iter())
            }
            GenericPattern::Enc(_) => {
                self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), ignore_pat_pad)
            }
        }
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a prefix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the prefix.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{ClearString, FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (bananas, ba, nan) = ("bananas", "ba", "nan");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_ba = GenericPattern::Enc(FheString::new(&ck, &ba, None));
    /// let clear_nan = GenericPattern::Clear(ClearString::new(nan.to_string()));
    ///
    /// let result1 = sk.starts_with(&enc_bananas, &enc_ba);
    /// let result2 = sk.starts_with(&enc_bananas, &clear_nan);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn starts_with(&self, str: &FheString, pat: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        if !trivial_or_enc_pat.is_padded() {
            return match pat {
                GenericPattern::Clear(pat) => self.clear_asciis_eq(str.chars().iter(), pat.str()),
                GenericPattern::Enc(pat) => self.asciis_eq(str.chars().iter(), pat.chars().iter()),
            };
        }

        let str_len = str.chars().len();
        let pat_len = trivial_or_enc_pat.chars().len();

        // In the padded pattern case we can remove the last char (as it's always null)
        let pat_chars = &trivial_or_enc_pat.chars()[..pat_len - 1];

        let null = FheAsciiChar::null(self);
        let str_chars = if !str.is_padded() && (str_len < pat_len - 1) {
            // If str = "xy" and pat = "xyz\0", then str[..] == pat[..2], but instead we have
            // to check if "xy\0" == pat[..3] (i.e. check that the actual pattern isn't longer)
            CharIter::Extended(str.chars().iter().chain(std::iter::once(&null)))
        } else {
            CharIter::Iter(str.chars().iter())
        };

        let str_pat = str_chars.into_iter().zip(pat_chars).par_bridge();

        self.asciis_eq_ignore_pat_pad(str_pat)
    }

    /// Returns `true` if the given pattern (either encrypted or clear) matches a suffix of this
    /// encrypted string.
    ///
    /// Returns `false` if the pattern does not match the suffix.
    ///
    /// The pattern to search for can be specified as either `GenericPattern::Clear` for a clear
    /// string or `GenericPattern::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::ciphertext::{ClearString, FheString, GenericPattern};
    /// use crate::server_key::gen_keys;
    ///
    /// let (ck, sk) = gen_keys();
    /// let (bananas, anas, nana) = ("bananas", "anas", "nana");
    ///
    /// let enc_bananas = FheString::new(&ck, &bananas, None);
    /// let enc_anas = GenericPattern::Enc(FheString::new(&ck, &anas, None));
    /// let clear_nana = GenericPattern::Clear(ClearString::new(nana.to_string()));
    ///
    /// let result1 = sk.ends_with(&enc_bananas, &enc_anas);
    /// let result2 = sk.ends_with(&enc_bananas, &clear_nana);
    ///
    /// let should_be_true = ck.key().decrypt_bool(&result1);
    /// let should_be_false = ck.key().decrypt_bool(&result2);
    ///
    /// assert!(should_be_true);
    /// assert!(!should_be_false);
    /// ```
    pub fn ends_with(&self, str: &FheString, pat: &GenericPattern) -> BooleanBlock {
        let trivial_or_enc_pat = match pat {
            GenericPattern::Clear(pat) => FheString::trivial(self, pat.str()),
            GenericPattern::Enc(pat) => pat.clone(),
        };

        match self.length_checks(str, &trivial_or_enc_pat) {
            IsMatch::Clear(val) => return self.key.create_trivial_boolean_block(val),
            IsMatch::Cipher(val) => return val,
            _ => (),
        }

        match pat {
            GenericPattern::Clear(pat) => {
                let (str_iter, clear_pat, iter) = self.clear_ends_with_cases(str, pat.str());

                self.clear_compare_shifted((str_iter, &clear_pat), iter.into_par_iter())
            }
            GenericPattern::Enc(pat) => {
                let null = (str.is_padded() ^ pat.is_padded()).then_some(FheAsciiChar::null(self));

                let (str_iter, pat_iter, iter) = self.ends_with_cases(str, pat, null.as_ref());

                self.compare_shifted((str_iter, pat_iter), iter.into_par_iter(), false)
            }
        }
    }
}
