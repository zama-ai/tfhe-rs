mod contains;
mod find;
mod replace;
mod split;
mod strip;

use crate::integer::BooleanBlock;
use crate::strings::ciphertext::{FheAsciiChar, FheString};
use crate::strings::server_key::{CharIter, FheStringIsEmpty, ServerKey};
use itertools::Itertools;
use std::ops::Range;

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
        let pat_len = pat.len();
        let str_len = str.len();

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
                FheStringIsEmpty::NoPadding(_) => IsMatch::Clear(false),
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
}

fn ends_with_cases<'a>(
    str: &'a FheString,
    pat: &'a FheString,
    null: Option<&'a FheAsciiChar>,
) -> (CharIter<'a>, CharIter<'a>, Range<usize>) {
    let pat_len = pat.len();
    let str_len = str.len();

    let range;

    let str_chars;
    let pat_chars;

    match (str.is_padded(), pat.is_padded()) {
        // If neither has padding we just check if pat matches the `pat_len` last chars or str
        (false, false) => {
            str_chars = str.chars().iter().collect_vec();
            pat_chars = pat.chars().iter().collect_vec();

            let start = str_len - pat_len;

            range = start..start + 1;
        }

        // If only str is padded we have to check all the possible padding cases. If str is 3
        // chars long, then it could be "xx\0", "x\0\0" or "\0\0\0", where x != '\0'
        (true, false) => {
            str_chars = str.chars()[..str_len - 1].iter().collect_vec();
            pat_chars = pat
                .chars()
                .iter()
                .chain(std::iter::once(null.unwrap()))
                .collect_vec();

            let diff = (str_len - 1) - pat_len;

            range = 0..diff + 1;
        }

        // If only pat is padded we have to check all the possible padding cases as well
        // If str = "abc" and pat = "abcd\0", we check if "abc\0" == pat[..4]
        (false, true) => {
            str_chars = str
                .chars()
                .iter()
                .chain(std::iter::once(null.unwrap()))
                .collect_vec();
            pat_chars = pat.chars().iter().collect_vec();

            if pat_len - 1 > str_len {
                // Pat without last char is longer than str so we check all the str chars
                range = 0..str_len + 1;
            } else {
                // Pat without last char is equal or shorter than str so we check the
                // `pat_len` - 1 last chars of str
                let start = str_len - (pat_len - 1);

                range = start..start + pat_len;
            };
        }

        (true, true) => {
            str_chars = str.chars().iter().collect_vec();
            pat_chars = pat.chars().iter().collect_vec();

            range = 0..str_len;
        }
    }

    (str_chars, pat_chars, range)
}

fn clear_ends_with_cases<'a>(
    str: &'a FheString,
    pat: &str,
) -> (CharIter<'a>, String, Range<usize>) {
    let pat_len = pat.len();
    let str_len = str.len();

    if str.is_padded() {
        let str_chars = str.chars()[..str_len - 1].iter().collect();
        let pat_chars = format!("{pat}\0");

        let diff = (str_len - 1) - pat_len;
        let range = 0..diff + 1;

        (str_chars, pat_chars, range)
    } else {
        let str_chars = str.chars().iter().collect();

        let start = str_len - pat_len;
        let range = start..start + 1;

        (str_chars, pat.to_owned(), range)
    }
}

fn contains_cases<'a>(
    str: &'a FheString,
    pat: &'a FheString,
    null: Option<&'a FheAsciiChar>,
) -> (CharIter<'a>, CharIter<'a>, Range<usize>) {
    let pat_len = pat.len();
    let str_len = str.len();

    let str_chars;
    let pat_chars;

    let range;

    if pat.is_padded() {
        pat_chars = pat.chars()[..pat_len - 1].iter().collect_vec();

        if str.is_padded() {
            str_chars = str.chars().iter().collect_vec();

            range = 0..str_len - 1;
        } else {
            str_chars = str
                .chars()
                .iter()
                .chain(std::iter::once(null.unwrap()))
                .collect_vec();

            range = 0..str_len;
        }
    } else {
        str_chars = str.chars().iter().collect_vec();
        pat_chars = pat.chars().iter().collect_vec();

        let diff = (str_len - pat_len) - if str.is_padded() { 1 } else { 0 };

        range = 0..diff + 1;
    }

    (str_chars, pat_chars, range)
}
