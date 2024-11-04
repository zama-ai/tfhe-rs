use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern};
use crate::strings::test_functions::{result_message_clear_pat, result_message_pat};
use crate::strings::Keys;
use std::time::Instant;

#[test]
fn test_contains_start_end() {
    let keys = Keys::new(PARAM_MESSAGE_2_CARRY_2);

    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for str in ["", "a", "abc", "b", "ab", "dddabc", "abceeee", "dddabceee"] {
                for pat in ["", "a", "abc"] {
                    keys.assert_contains(str, Some(str_pad), pat, Some(pat_pad));
                    keys.assert_starts_with(str, Some(str_pad), pat, Some(pat_pad));
                    keys.assert_ends_with(str, Some(str_pad), pat, Some(pat_pad));
                }
            }
        }
    }
}

impl Keys {
    pub fn assert_contains(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.contains(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = GenericPattern::Enc(FheString::new(&self.ck, pat, pat_pad));
        let clear_pat = GenericPattern::Clear(ClearString::new(pat.to_string()));

        let start = Instant::now();
        let result = self.sk.contains(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mContains:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let result = self.sk.contains(&enc_str, &clear_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mContains:\x1b[0m");
        result_message_clear_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_ends_with(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.ends_with(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = GenericPattern::Enc(FheString::new(&self.ck, pat, pat_pad));
        let clear_pat = GenericPattern::Clear(ClearString::new(pat.to_string()));

        let start = Instant::now();
        let result = self.sk.ends_with(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEnds_with:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let result = self.sk.ends_with(&enc_str, &clear_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEnds_with:\x1b[0m");
        result_message_clear_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_starts_with(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.starts_with(pat);

        let enc_str = FheString::new(&self.ck, str, str_pad);
        let enc_pat = GenericPattern::Enc(FheString::new(&self.ck, pat, pat_pad));
        let clear_pat = GenericPattern::Clear(ClearString::new(pat.to_string()));

        let start = Instant::now();
        let result = self.sk.starts_with(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mStarts_with:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let result = self.sk.starts_with(&enc_str, &clear_pat);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mStarts_with:\x1b[0m");
        result_message_clear_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }
}
