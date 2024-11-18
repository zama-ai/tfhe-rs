use crate::integer::{BooleanBlock, ServerKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern, GenericPatternRef};
use crate::strings::server_key::{FheStringIsEmpty, FheStringLen};
use crate::strings::test::TestKind;
use crate::strings::test_functions::{
    result_message, result_message_clear_pat, result_message_clear_rhs, result_message_pat,
    result_message_rhs,
};
use crate::strings::TestKeys;
use std::time::{Duration, Instant};

#[test]
fn test_len_is_empty_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            keys.check_len_fhe_string_vs_rust_str(str, Some(pad));
            keys.check_is_empty_fhe_string_vs_rust_str(str, Some(pad));
        }
    }
}

#[test]
fn test_len_is_empty() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.check_len_fhe_string_vs_rust_str("", Some(1));
    keys.check_is_empty_fhe_string_vs_rust_str("", Some(1));

    keys.check_len_fhe_string_vs_rust_str("abc", Some(1));
    keys.check_is_empty_fhe_string_vs_rust_str("abc", Some(1));
}

#[test]
fn test_encrypt_decrypt_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            keys.check_encrypt_decrypt_fhe_string_vs_rust_str(str, Some(pad));
        }
    }
}

#[test]
fn test_encrypt_decrypt() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            keys.check_encrypt_decrypt_fhe_string_vs_rust_str(str, Some(pad));
        }
    }
}

#[test]
fn test_strip_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for pat in ["", "a", "abc"] {
                for str in ["", "a", "abc", "b", "ab", "dddabc", "abceeee", "dddabceee"] {
                    keys.check_strip_prefix_fhe_string_vs_rust_str(
                        str,
                        Some(str_pad),
                        pat,
                        Some(pat_pad),
                    );
                    keys.check_strip_suffix_fhe_string_vs_rust_str(
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
fn test_strip() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );
    keys.check_strip_prefix_fhe_string_vs_rust_str("abc", Some(1), "a", Some(1));
    keys.check_strip_suffix_fhe_string_vs_rust_str("abc", Some(1), "c", Some(1));

    keys.check_strip_prefix_fhe_string_vs_rust_str("abc", Some(1), "d", Some(1));
    keys.check_strip_suffix_fhe_string_vs_rust_str("abc", Some(1), "d", Some(1));
}

const TEST_CASES_COMP: [&str; 5] = ["", "a", "aa", "ab", "abc"];

#[test]
fn test_comparisons_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in TEST_CASES_COMP {
                for rhs in TEST_CASES_COMP {
                    keys.check_comp_fhe_string_vs_rust_str(str, Some(str_pad), rhs, Some(rhs_pad));
                }
            }
        }
    }
}

#[test]
fn test_comparisons() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.check_comp_fhe_string_vs_rust_str("a", Some(1), "a", Some(1));

    keys.check_comp_fhe_string_vs_rust_str("a", Some(1), "b", Some(1));
}

impl TestKeys {
    pub fn check_len_fhe_string_vs_rust_str(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.len();

        let enc_str = self.encrypt_string(str, str_pad);

        let start = Instant::now();
        let result = self.sk.len(&enc_str);
        let end = Instant::now();

        let dec = match result {
            FheStringLen::NoPadding(clear_len) => clear_len,
            FheStringLen::Padding(enc_len) => self.ck.decrypt_radix::<u32>(&enc_len) as usize,
        };

        println!("\n\x1b[1mLen:\x1b[0m");
        result_message(str, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_is_empty_fhe_string_vs_rust_str(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.is_empty();

        let enc_str = self.encrypt_string(str, str_pad);

        let start = Instant::now();
        let result = self.sk.is_empty(&enc_str);
        let end = Instant::now();

        let dec = match result {
            FheStringIsEmpty::NoPadding(clear_len) => clear_len,
            FheStringIsEmpty::Padding(enc_len) => self.ck.decrypt_bool(&enc_len),
        };

        println!("\n\x1b[1mIs_empty:\x1b[0m");
        result_message(str, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_encrypt_decrypt_fhe_string_vs_rust_str(&self, str: &str, str_pad: Option<u32>) {
        let enc_str = self.encrypt_string(str, str_pad);

        let dec = self.ck.decrypt_ascii(&enc_str);

        println!("\n\x1b[1mEncrypt/Decrypt:\x1b[0m");
        result_message(str, str, &dec, Duration::from_nanos(0));

        assert_eq!(str, &dec);
    }

    pub fn check_strip_prefix_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.strip_prefix(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));
        let clear_pat = GenericPattern::Clear(ClearString::new(pat.to_string()));

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_prefix(&enc_str, enc_pat.as_ref());
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.decrypt_bool(&is_some);
        if !dec_is_some {
            // When it's None, the FheString returned is the original str
            assert_eq!(dec_result, str);
        }

        let dec = dec_is_some.then_some(dec_result.as_str());

        println!("\n\x1b[1mStrip_prefix:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_prefix(&enc_str, clear_pat.as_ref());
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.decrypt_bool(&is_some);
        if !dec_is_some {
            // When it's None, the FheString returned is the original str
            assert_eq!(dec_result, str);
        }

        let dec = dec_is_some.then_some(dec_result.as_str());

        println!("\n\x1b[1mStrip_prefix:\x1b[0m");
        result_message_clear_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_strip_suffix_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.strip_suffix(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));
        let clear_pat = GenericPattern::Clear(ClearString::new(pat.to_string()));

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_suffix(&enc_str, enc_pat.as_ref());
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.decrypt_bool(&is_some);
        if !dec_is_some {
            // When it's None, the FheString returned is the original str
            assert_eq!(dec_result, str);
        }

        let dec = dec_is_some.then_some(dec_result.as_str());

        println!("\n\x1b[1mStrip_suffix:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let (result, is_some) = self.sk.strip_suffix(&enc_str, clear_pat.as_ref());
        let end = Instant::now();

        let dec_result = self.ck.decrypt_ascii(&result);
        let dec_is_some = self.ck.decrypt_bool(&is_some);
        if !dec_is_some {
            // When it's None, the FheString returned is the original str
            assert_eq!(dec_result, str);
        }

        let dec = dec_is_some.then_some(dec_result.as_str());

        println!("\n\x1b[1mStrip_suffix:\x1b[0m");
        result_message_clear_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_comp_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        rhs: &str,
        rhs_pad: Option<u32>,
    ) {
        let enc_lhs = self.encrypt_string(str, str_pad);
        let enc_rhs = GenericPattern::Enc(self.encrypt_string(rhs, rhs_pad));
        let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

        #[allow(clippy::type_complexity)]
        let ops: [(
            bool,
            fn(&ServerKey, &FheString, GenericPatternRef<'_>) -> BooleanBlock,
        ); 6] = [
            (str == rhs, ServerKey::string_eq),
            (str != rhs, ServerKey::string_ne),
            (str >= rhs, ServerKey::string_ge),
            (str <= rhs, ServerKey::string_le),
            (str > rhs, ServerKey::string_gt),
            (str < rhs, ServerKey::string_lt),
        ];

        for (expected_result, encrypted_op) in ops {
            // Encrypted rhs
            let start = Instant::now();
            let result = encrypted_op(&self.sk, &enc_lhs, enc_rhs.as_ref());
            let end = Instant::now();

            let dec_result = self.ck.decrypt_bool(&result);

            println!("\n\x1b[1mEq:\x1b[0m");
            result_message_rhs(
                str,
                rhs,
                expected_result,
                dec_result,
                end.duration_since(start),
            );
            assert_eq!(dec_result, expected_result);

            // Clear rhs
            let start = Instant::now();
            let result_eq = encrypted_op(&self.sk, &enc_lhs, clear_rhs.as_ref());
            let end = Instant::now();

            let dec_eq = self.ck.decrypt_bool(&result_eq);

            println!("\n\x1b[1mEq:\x1b[0m");
            result_message_clear_rhs(str, rhs, expected_result, dec_eq, end.duration_since(start));
            assert_eq!(dec_eq, expected_result);
        }
    }
}
