use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::strings::ciphertext::UIntArg;
use crate::strings::test::TestKind;
use crate::strings::test_functions::result_message_rhs;
use crate::strings::TestKeys;
use std::time::Instant;

const TEST_CASES_CONCAT: [&str; 5] = ["", "a", "ab", "abc", "abcd"];

#[test]
fn test_concat_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in TEST_CASES_CONCAT {
                for rhs in TEST_CASES_CONCAT {
                    keys.assert_concat(str, Some(str_pad), rhs, Some(rhs_pad));
                }
            }
        }
    }
}

#[test]
fn test_concat() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.assert_concat("a", Some(1), "b", Some(1));
}

#[test]
fn test_repeat_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for n in 0..3 {
            for str in TEST_CASES_CONCAT {
                for max in n..n + 2 {
                    keys.assert_repeat(str, Some(str_pad), n, max);
                }
            }
        }
    }
}

#[test]
fn test_repeat() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.assert_repeat("a", Some(1), 1, 2);
}

impl TestKeys {
    pub fn assert_concat(&self, str: &str, str_pad: Option<u32>, rhs: &str, rhs_pad: Option<u32>) {
        let expected = str.to_owned() + rhs;

        let enc_lhs = self.encrypt_string(str, str_pad);
        let enc_rhs = self.encrypt_string(rhs, rhs_pad);

        let start = Instant::now();
        let result = self.sk.concat(&enc_lhs, &enc_rhs);
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!("\n\x1b[1mConcat (+):\x1b[0m");
        result_message_rhs(str, rhs, &expected, &dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_repeat(&self, str: &str, str_pad: Option<u32>, n: u16, max: u16) {
        let expected = str.repeat(n as usize);

        let enc_str = self.encrypt_string(str, str_pad);

        // Clear n
        let start = Instant::now();
        let result = self.sk.repeat(&enc_str, &UIntArg::Clear(n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1mRepeat:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            n,
            expected,
            dec,
            end.duration_since(start),
        );
        assert_eq!(dec, expected);

        // Encrypted n
        let enc_n = self.encrypt_u16(n, Some(max));

        let start = Instant::now();
        let result = self.sk.repeat(&enc_str, &UIntArg::Enc(enc_n));
        let end = Instant::now();

        let dec = self.ck.decrypt_ascii(&result);

        println!(
            "\n\x1b[1mRepeat:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            n,
            expected,
            dec,
            end.duration_since(start),
        );
        assert_eq!(dec, expected);
    }
}
