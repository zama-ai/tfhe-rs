mod contains;
mod find;
mod replace;
mod split;
mod strip;

use crate::ciphertext::{FheAsciiChar, FheString};
use crate::server_key::{CharIter, FheStringIsEmpty, ServerKey};
use std::ops::Range;
use tfhe::integer::BooleanBlock;

// Useful for handling cases in which we know if there is or there isn't a match just by looking at
// the lengths
enum IsMatch {
    Clear(bool),
    Cipher(BooleanBlock),
    None,
}

// `length_checks` allow us to return early in the pattern matching functions, while the other
// methods below contain logic for the different cases
impl ServerKey {
    fn length_checks(&self, str: &FheString, pat: &FheString) -> IsMatch {
        let pat_len = pat.chars().len();
        let str_len = str.chars().len();

        // If the pattern is empty it will match any string, this is the behavior of core::str
        // Note that this doesn't handle the case where pattern is empty and has > 1 padding zeros
        if pat_len == 0 || (pat.is_padded() && pat_len == 1) {
            return IsMatch::Clear(true);
        }

        // If our string is an empty string we are just looking if the pattern is also empty (the
        // only case remaining is if pattern padding > 1).
        if str_len == 0 || (str.is_padded() && str_len == 1) {
            return match self.is_empty(pat) {
                FheStringIsEmpty::Padding(value) => IsMatch::Cipher(value),

                _ => IsMatch::Clear(false),
            };
        }

        if !pat.is_padded() {
            // A pattern without padding cannot be contained in a shorter string without padding
            if !str.is_padded() && (str_len < pat_len) {
                return IsMatch::Clear(false);
            }

            // A pattern without padding cannot be contained in a string with padding that is
            // shorter or of the same length
            if str.is_padded() && (str_len <= pat_len) {
                return IsMatch::Clear(false);
            }
        }

        IsMatch::None
    }

    fn ends_with_cases<'a>(
        &'a self,
        str: &'a FheString,
        pat: &'a FheString,
        null: Option<&'a FheAsciiChar>,
    ) -> (CharIter, CharIter, Range<usize>) {
        let pat_len = pat.chars().len();
        let str_len = str.chars().len();

        match (str.is_padded(), pat.is_padded()) {
            // If neither has padding we just check if pat matches the `pat_len` last chars or str
            (false, false) => {
                let str_chars = str.chars().iter();
                let pat_chars = pat.chars().iter();

                let start = str_len - pat_len;

                let range = start..start + 1;

                (CharIter::Iter(str_chars), CharIter::Iter(pat_chars), range)
            }

            // If only str is padded we have to check all the possible padding cases. If str is 3
            // chars long, then it could be "xx\0", "x\0\0" or "\0\0\0", where x != '\0'
            (true, false) => {
                let str_chars = str.chars()[..str_len - 1].iter();
                let pat_chars = pat.chars().iter().chain(std::iter::once(null.unwrap()));

                let diff = (str_len - 1) - pat_len;

                let range = 0..diff + 1;

                (
                    CharIter::Iter(str_chars),
                    CharIter::Extended(pat_chars),
                    range,
                )
            }

            // If only pat is padded we have to check all the possible padding cases as well
            // If str = "abc" and pat = "abcd\0", we check if "abc\0" == pat[..4]
            (false, true) => {
                let (str_chars, pat_chars, range) = if pat_len - 1 > str_len {
                    // Pat without last char is longer than str so we check all the str chars
                    (
                        str.chars().iter().chain(std::iter::once(null.unwrap())),
                        pat.chars().iter(),
                        0..str_len + 1,
                    )
                } else {
                    // Pat without last char is equal or shorter than str so we check the
                    // `pat_len` - 1 last chars of str
                    let start = str_len - (pat_len - 1);
                    (
                        str.chars().iter().chain(std::iter::once(null.unwrap())),
                        pat.chars()[..pat_len - 1].iter(),
                        start..start + pat_len,
                    )
                };

                (
                    CharIter::Extended(str_chars),
                    CharIter::Iter(pat_chars),
                    range,
                )
            }

            (true, true) => {
                let str_chars = str.chars().iter();
                let pat_chars = pat.chars().iter();

                let range = 0..str_len;

                (CharIter::Iter(str_chars), CharIter::Iter(pat_chars), range)
            }
        }
    }

    fn clear_ends_with_cases<'a>(
        &'a self,
        str: &'a FheString,
        pat: &str,
    ) -> (CharIter, String, Range<usize>) {
        let pat_len = pat.len();
        let str_len = str.chars().len();

        if str.is_padded() {
            let str_chars = str.chars()[..str_len - 1].iter();
            let mut pat_chars = pat.to_owned();

            pat_chars.push('\0');

            let diff = (str_len - 1) - pat_len;
            let range = 0..diff + 1;

            (CharIter::Iter(str_chars), pat_chars, range)
        } else {
            let start = str_len - pat_len;
            let range = start..start + 1;

            (CharIter::Iter(str.chars().iter()), pat.to_owned(), range)
        }
    }

    fn contains_cases<'a>(
        &'a self,
        str: &'a FheString,
        pat: &'a FheString,
        null: Option<&'a FheAsciiChar>,
    ) -> (CharIter, CharIter, Range<usize>) {
        let pat_len = pat.chars().len();
        let str_len = str.chars().len();

        match (str.is_padded(), pat.is_padded()) {
            (_, false) => {
                let diff = (str_len - pat_len) - if str.is_padded() { 1 } else { 0 };

                let range = 0..diff + 1;

                (
                    CharIter::Iter(str.chars().iter()),
                    CharIter::Iter(pat.chars().iter()),
                    range,
                )
            }

            (true, true) => {
                let pat_chars = pat.chars()[..pat_len - 1].iter();

                let range = 0..str_len - 1;

                (
                    CharIter::Iter(str.chars().iter()),
                    CharIter::Iter(pat_chars),
                    range,
                )
            }

            (false, true) => {
                let pat_chars = pat.chars()[..pat_len - 1].iter();
                let str_chars = str.chars().iter().chain(std::iter::once(null.unwrap()));

                let range = 0..str_len;

                (
                    CharIter::Extended(str_chars),
                    CharIter::Iter(pat_chars),
                    range,
                )
            }
        }
    }
}
