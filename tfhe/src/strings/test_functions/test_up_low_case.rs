use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern};
use crate::strings::test_functions::{
    result_message, result_message_clear_rhs, result_message_rhs,
};
use crate::strings::Keys;
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
fn test_to_lower_upper_case() {
    let keys = Keys::new(PARAM_MESSAGE_2_CARRY_2);

    for str_pad in 0..2 {
        for str in UP_LOW_CASE {
            keys.assert_to_lowercase(str, Some(str_pad));
            keys.assert_to_uppercase(str, Some(str_pad));
        }
    }
}

#[test]
fn test_eq_ignore_case() {
    let keys = Keys::new(PARAM_MESSAGE_2_CARRY_2);

    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in UP_LOW_CASE {
                for rhs in UP_LOW_CASE {
                    keys.assert_eq_ignore_case(str, Some(str_pad), rhs, Some(rhs_pad));
                }
            }
        }
    }
}

impl Keys {
    pub fn assert_eq_ignore_case(
        &self,
        str: &str,
        str_pad: Option<u32>,
        rhs: &str,
        rhs_pad: Option<u32>,
    ) {
        let expected = str.eq_ignore_ascii_case(rhs);

        let enc_lhs = FheString::new(&self.ck, str, str_pad);
        let enc_rhs = GenericPattern::Enc(FheString::new(&self.ck, rhs, rhs_pad));
        let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

        let start = Instant::now();
        let result = self.sk.eq_ignore_case(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEq_ignore_case:\x1b[0m");
        result_message_rhs(str, rhs, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);

        let start = Instant::now();
        let result = self.sk.eq_ignore_case(&enc_lhs, &clear_rhs);
        let end = Instant::now();

        let dec = self.ck.decrypt_bool(&result);

        println!("\n\x1b[1mEq_ignore_case:\x1b[0m");
        result_message_clear_rhs(str, rhs, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_to_lowercase(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_lowercase();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_lowercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!("\n\x1b[1mTo_lowercase:\x1b[0m");
        result_message(str, &expected, &dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_to_uppercase(&self, str: &str, str_pad: Option<u32>) {
        let expected = str.to_uppercase();

        let enc_str = FheString::new(&self.ck, str, str_pad);

        let start = Instant::now();
        let result = self.sk.to_uppercase(&enc_str);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!("\n\x1b[1mTo_upperrcase:\x1b[0m");
        result_message(str, &expected, &dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }
}
