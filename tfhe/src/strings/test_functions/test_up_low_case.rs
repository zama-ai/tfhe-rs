use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::strings::ciphertext::{ClearString, GenericPattern};
use crate::strings::test::TestKind;
use crate::strings::test_functions::{
    result_message, result_message_clear_rhs, result_message_rhs,
};
use crate::strings::TestKeys;
use std::time::Instant;

const UP_LOW_CASE: [&str; 21] = [
    "",  //
    "@", // just before 'A'
    "A", "Z", //
    "[", "\\", "]", "^", "_", "`", // chars between 'Z' and 'a'
    "a", "z", //
    "{", // just after 'z'
    "a ", " a", "A", "A ", " A", "aA", " aA", "aA ",
];

#[test]
fn test_to_lower_upper_case_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for str in UP_LOW_CASE {
            keys.check_to_lowercase_fhe_string_vs_rust_str(str, Some(str_pad));
            keys.check_to_uppercase_fhe_string_vs_rust_str(str, Some(str_pad));
        }
    }
}

#[test]
fn test_to_lower_upper_case() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.check_to_lowercase_fhe_string_vs_rust_str("ab", Some(1));
    keys.check_to_lowercase_fhe_string_vs_rust_str("AB", Some(1));

    keys.check_to_uppercase_fhe_string_vs_rust_str("AB", Some(1));
    keys.check_to_uppercase_fhe_string_vs_rust_str("ab", Some(1));
}

#[test]
fn test_eq_ignore_case_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in UP_LOW_CASE {
                for rhs in UP_LOW_CASE {
                    keys.check_eq_ignore_case_fhe_string_vs_rust_str(
                        str,
                        Some(str_pad),
                        rhs,
                        Some(rhs_pad),
                    );
                }
            }
        }
    }
}

#[test]
fn test_eq_ignore_case() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.check_eq_ignore_case_fhe_string_vs_rust_str("aB", Some(1), "Ab", Some(1));
    keys.check_eq_ignore_case_fhe_string_vs_rust_str("aB", Some(1), "Ac", Some(1));
}

impl TestKeys {
    pub fn check_eq_ignore_case_fhe_string_vs_rust_str(
        &self,
        str: &str,
        str_pad: Option<u32>,
        rhs: &str,
        rhs_pad: Option<u32>,
    ) {
        let expected = str.eq_ignore_ascii_case(rhs);

        let enc_lhs = self.encrypt_string(str, str_pad);
        let enc_rhs = GenericPattern::Enc(self.encrypt_string(rhs, rhs_pad));
        let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

        let start = Instant::now();
        let result = self.sk.eq_ignore_case(&enc_lhs, enc_rhs.as_ref());
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEq_ignore_case:\x1b[0m");
        result_message_rhs(str, rhs, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let result = self.sk.eq_ignore_case(&enc_lhs, clear_rhs.as_ref());
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEq_ignore_case:\x1b[0m");
        result_message_clear_rhs(str, rhs, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_to_lowercase_fhe_string_vs_rust_str(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_lowercase();

        let enc_str = self.encrypt_string(str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_lowercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!("\n\x1b[1mTo_lowercase:\x1b[0m");
        result_message(str, &expected, &dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn check_to_uppercase_fhe_string_vs_rust_str(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_uppercase();

        let enc_str = self.encrypt_string(str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_uppercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!("\n\x1b[1mTo_upperrcase:\x1b[0m");
        result_message(str, &expected, &dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }
}
