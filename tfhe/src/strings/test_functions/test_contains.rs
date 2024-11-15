use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::strings::ciphertext::{ClearString, GenericPattern};
use crate::strings::test::TestKind;
use crate::strings::test_functions::{result_message_clear_pat, result_message_pat};
use crate::strings::TestKeys;
use std::time::Instant;

#[test]
fn test_contains_start_end_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for str in ["", "a", "abc", "b", "ab", "dddabc", "abceeee", "dddabceee"] {
                for pat in ["", "a", "abc"] {
                    keys.check_contains_fhe_string_vs_rust_str(
                        str,
                        Some(str_pad),
                        pat,
                        Some(pat_pad),
                    );
                    keys.check_starts_with_fhe_string_vs_rust_str(
                        str,
                        Some(str_pad),
                        pat,
                        Some(pat_pad),
                    );
                    keys.check_ends_with_fhe_string_vs_rust_str(
                        str,
                        Some(str_pad),
                        pat,
                        Some(pat_pad),
                    );
                }
            }
        }
    }
}

#[test]
fn test_contains_start_end() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.check_contains_fhe_string_vs_rust_str("ab", Some(1), "a", Some(1));
    keys.check_contains_fhe_string_vs_rust_str("ab", Some(1), "c", Some(1));

    keys.check_starts_with_fhe_string_vs_rust_str("ab", Some(1), "a", Some(1));
    keys.check_starts_with_fhe_string_vs_rust_str("ab", Some(1), "c", Some(1));

    keys.check_ends_with_fhe_string_vs_rust_str("ab", Some(1), "b", Some(1));
    keys.check_ends_with_fhe_string_vs_rust_str("ab", Some(1), "c", Some(1));
}

impl TestKeys {
    pub fn check_contains_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.contains(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));
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

    pub fn check_ends_with_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.ends_with(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));
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

    pub fn check_starts_with_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.starts_with(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));
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
