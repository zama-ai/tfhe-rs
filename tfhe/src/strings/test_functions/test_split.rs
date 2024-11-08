use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::strings::ciphertext::{GenericPattern, UIntArg};
use crate::strings::server_key::FheStringIterator;
use crate::strings::test::TestKind;
use crate::strings::test_functions::result_message_pat;
use crate::strings::TestKeys;
use std::time::Instant;

const TEST_CASES_SPLIT: [(&str, &str); 21] = [
    ("", ""),
    ("a", ""),
    ("abcd", ""),
    ("", "a"),
    ("a", "a"),
    ("a", "A"),
    ("aa", "a"),
    ("ab", "a"),
    ("ba", "a"),
    ("bb", "a"),
    ("aaa", "a"),
    ("aab", "a"),
    ("aba", "a"),
    ("baa", "a"),
    ("abb", "a"),
    ("bab", "a"),
    ("bba", "a"),
    ("", "ab"),
    ("ab", "ab"),
    ("abab", "ab"),
    ("baba", "ab"),
];

#[test]
fn test_split_trivial() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Trivial,
    );

    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for (str, pat) in TEST_CASES_SPLIT {
                keys.assert_split_once(str, Some(str_pad), pat, Some(pat_pad));
                keys.assert_rsplit_once(str, Some(str_pad), pat, Some(pat_pad));
                keys.assert_split(str, Some(str_pad), pat, Some(pat_pad));
                keys.assert_rsplit(str, Some(str_pad), pat, Some(pat_pad));

                for n in 0..3 {
                    for max in n..n + 2 {
                        keys.assert_splitn(str, Some(str_pad), pat, Some(pat_pad), n, max);
                        keys.assert_rsplitn(str, Some(str_pad), pat, Some(pat_pad), n, max);
                    }
                }

                keys.assert_split_terminator(str, Some(str_pad), pat, Some(pat_pad));
                keys.assert_rsplit_terminator(str, Some(str_pad), pat, Some(pat_pad));
                keys.assert_split_inclusive(str, Some(str_pad), pat, Some(pat_pad));
            }
        }
    }
}

#[test]
fn test_split() {
    let keys = TestKeys::new(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        TestKind::Encrypted,
    );

    keys.assert_split_once("", Some(1), "", Some(1));
    keys.assert_rsplit_once("", Some(1), "", Some(1));
    keys.assert_split("", Some(1), "", Some(1));
    keys.assert_rsplit("", Some(1), "", Some(1));

    keys.assert_splitn("", Some(1), "", Some(1), 1, 2);
    keys.assert_rsplitn("", Some(1), "", Some(1), 1, 2);

    keys.assert_split_terminator("", Some(1), "", Some(1));
    keys.assert_rsplit_terminator("", Some(1), "", Some(1));
    keys.assert_split_inclusive("", Some(1), "", Some(1));
}

impl TestKeys {
    pub fn assert_split_once(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.split_once(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let start = Instant::now();
        let (lhs, rhs, is_some) = self.sk.split_once(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_lhs = self.ck.decrypt_ascii(&lhs);
        let dec_rhs = self.ck.decrypt_ascii(&rhs);
        let dec_is_some = self.ck.decrypt_bool(&is_some);

        let dec = dec_is_some.then_some((dec_lhs.as_str(), dec_rhs.as_str()));

        println!("\n\x1b[1mSplit_once:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_rsplit_once(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let expected = str.rsplit_once(pat);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let start = Instant::now();
        let (lhs, rhs, is_some) = self.sk.rsplit_once(&enc_str, &enc_pat);
        let end = Instant::now();

        let dec_lhs = self.ck.decrypt_ascii(&lhs);
        let dec_rhs = self.ck.decrypt_ascii(&rhs);
        let dec_is_some = self.ck.decrypt_bool(&is_some);

        let dec = dec_is_some.then_some((dec_lhs.as_str(), dec_rhs.as_str()));

        println!("\n\x1b[1mRsplit_once:\x1b[0m");
        result_message_pat(str, pat, expected, dec, end.duration_since(start));

        assert_eq!(dec, expected);
    }

    pub fn assert_split(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.split(pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split(&enc_str, &enc_pat);
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        println!("\n\x1b[1mSplit:\x1b[0m");
        result_message_pat(str, pat, &expected, &dec_as_str, end.duration_since(start));

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplit(&self, str: &str, str_pad: Option<u32>, pat: &str, pat_pad: Option<u32>) {
        let mut expected: Vec<_> = str.rsplit(pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplit(&enc_str, &enc_pat);
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        println!("\n\x1b[1mRsplit:\x1b[0m");
        result_message_pat(str, pat, &expected, &dec_as_str, end.duration_since(start));

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_split_terminator(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let mut expected: Vec<_> = str.split_terminator(pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split_terminator(&enc_str, &enc_pat);
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        println!("\n\x1b[1mSplit_terminator:\x1b[0m");
        result_message_pat(str, pat, &expected, &dec_as_str, end.duration_since(start));

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplit_terminator(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let mut expected: Vec<_> = str.rsplit_terminator(pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplit_terminator(&enc_str, &enc_pat);
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        println!("\n\x1b[1mRsplit_terminator:\x1b[0m");
        result_message_pat(str, pat, &expected, &dec_as_str, end.duration_since(start));

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_split_inclusive(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
    ) {
        let mut expected: Vec<_> = str.split_inclusive(pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.split_inclusive(&enc_str, &enc_pat);
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        println!("\n\x1b[1mSplit_inclusive:\x1b[0m");
        result_message_pat(str, pat, &expected, &dec_as_str, end.duration_since(start));

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_splitn(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
        n: u16,
        max: u16,
    ) {
        let mut expected: Vec<_> = str.splitn(n as usize, pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.splitn(&enc_str, &enc_pat, UIntArg::Clear(n));
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        println!(
            "\n\x1b[1mSplitn:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            pat,
            n,
            expected,
            dec,
            end.duration_since(start),
        );

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);

        let enc_n = self.encrypt_u16(n, Some(max));
        results.clear();

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.splitn(&enc_str, &enc_pat, UIntArg::Enc(enc_n));
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        println!(
            "\n\x1b[1mSplitn:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            pat,
            n,
            expected,
            dec,
            end.duration_since(start),
        );

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }

    pub fn assert_rsplitn(
        &self,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
        n: u16,
        max: u16,
    ) {
        let mut expected: Vec<_> = str.rsplitn(n as usize, pat).map(Some).collect();
        expected.push(None);

        let enc_str = self.encrypt_string(str, str_pad);
        let enc_pat = GenericPattern::Enc(self.encrypt_string(pat, pat_pad));

        let mut results = Vec::with_capacity(expected.len());

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplitn(&enc_str, &enc_pat, UIntArg::Clear(n));
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        println!(
            "\n\x1b[1mRsplitn:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (clear): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            pat,
            n,
            expected,
            dec,
            end.duration_since(start),
        );

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);

        let enc_n = self.encrypt_u16(n, Some(max));
        results.clear();

        // Call next enough times
        let start = Instant::now();
        let mut split_iter = self.sk.rsplitn(&enc_str, &enc_pat, UIntArg::Enc(enc_n));
        for _ in 0..expected.len() {
            results.push(split_iter.next(&self.sk))
        }
        let end = Instant::now();

        // Collect the decrypted results properly
        let dec: Vec<_> = results
            .iter()
            .map(|(result, is_some)| {
                let dec_is_some = self.ck.decrypt_bool(is_some);

                dec_is_some.then_some(self.ck.decrypt_ascii(result))
            })
            .collect();

        println!(
            "\n\x1b[1mRsplitn:\x1b[0m\n\
            \x1b[1;32m--------------------------------\x1b[0m\n\
            \x1b[1;32;1mString: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mPattern: \x1b[0m\x1b[0;33m{:?}\x1b[0m\n\
            \x1b[1;32;1mTimes (encrypted): \x1b[0m{}\n\
            \x1b[1;32;1mClear API Result: \x1b[0m{:?}\n\
            \x1b[1;32;1mT-fhe API Result: \x1b[0m{:?}\n\
            \x1b[1;34mExecution Time: \x1b[0m{:?}\n\
            \x1b[1;32m--------------------------------\x1b[0m",
            str,
            pat,
            n,
            expected,
            dec,
            end.duration_since(start),
        );

        let dec_as_str: Vec<_> = dec
            .iter()
            .map(|option| option.as_ref().map(|s| s.as_str()))
            .collect();

        assert_eq!(dec_as_str, expected);
    }
}
