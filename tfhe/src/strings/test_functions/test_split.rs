use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::PBSParameters;
use crate::strings::ciphertext::{
    ClearString, FheString, GenericPattern, GenericPatternRef, UIntArg,
};
use crate::strings::server_key::FheStringIterator;
use std::iter::once;
use std::sync::Arc;

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
fn string_split_once_test_parameterized() {
    string_split_once_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_split_once_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> Option<(&'a str, &'a str)>,
        fn(&ServerKey, &FheString, GenericPatternRef<'_>) -> (FheString, FheString, BooleanBlock),
    ); 2] = [
        (
            |lhs: &str, rhs: &str| lhs.split_once(rhs),
            |a, b, c| ServerKey::split_once(a, b, c),
        ),
        (
            |lhs: &str, rhs: &str| lhs.rsplit_once(rhs),
            |a, b, c| ServerKey::rsplit_once(a, b, c),
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_split_once_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_split_once_test_impl<P, T>(
    param: P,
    mut split_once_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> Option<(&'a str, &'a str)>,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a FheString, GenericPatternRef<'a>),
        (FheString, FheString, BooleanBlock),
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    split_once_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for (str, pat) in TEST_CASES_SPLIT {
                let expected = clear_function(str, pat);

                let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                let enc_rhs = GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                for rhs in [enc_rhs, clear_rhs] {
                    let (split1, split2, is_some) =
                        split_once_executor.execute((&enc_lhs, rhs.as_ref()));

                    let dec_split1 = cks.decrypt_ascii(&split1);

                    let dec_split2 = cks.decrypt_ascii(&split2);

                    let dec_is_some = cks.decrypt_bool(&is_some);

                    let dec = dec_is_some.then_some((dec_split1.as_str(), dec_split2.as_str()));

                    assert_eq!(expected, dec)
                }
            }
        }
    }
    // encrypted
    {
        let str = "aba";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["a", "c"] {
            let expected = clear_function(str, rhs);

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let (split1, split2, is_some) =
                    split_once_executor.execute((&enc_lhs, rhs.as_ref()));

                let dec_split1 = cks.decrypt_ascii(&split1);

                let dec_split2 = cks.decrypt_ascii(&split2);

                let dec_is_some = cks.decrypt_bool(&is_some);

                let dec = dec_is_some.then_some((dec_split1.as_str(), dec_split2.as_str()));

                assert_eq!(expected, dec)
            }
        }
    }
}

#[test]
fn string_split_test_parameterized() {
    string_split_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_split_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> Box<dyn Iterator<Item = &'a str> + 'a>,
        fn(&ServerKey, &FheString, GenericPatternRef<'_>) -> Box<dyn FheStringIterator>,
    ); 5] = [
        (
            |lhs: &str, rhs: &str| Box::new(lhs.split(rhs)),
            |a, b, c| Box::new(ServerKey::split(a, b, c)),
        ),
        (
            |lhs: &str, rhs: &str| Box::new(lhs.rsplit(rhs)),
            |a, b, c| Box::new(ServerKey::rsplit(a, b, c)),
        ),
        (
            |lhs: &str, rhs: &str| Box::new(lhs.split_terminator(rhs)),
            |a, b, c| Box::new(ServerKey::split_terminator(a, b, c)),
        ),
        (
            |lhs: &str, rhs: &str| Box::new(lhs.rsplit_terminator(rhs)),
            |a, b, c| Box::new(ServerKey::rsplit_terminator(a, b, c)),
        ),
        (
            |lhs: &str, rhs: &str| Box::new(lhs.split_inclusive(rhs)),
            |a, b, c| Box::new(ServerKey::split_inclusive(a, b, c)),
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_split_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_split_test_impl<P, T>(
    param: P,
    mut split_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> Box<dyn Iterator<Item = &'a str> + 'a>,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), Box<dyn FheStringIterator>>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    split_executor.setup(&cks2, sks.clone());

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for (str, pat) in TEST_CASES_SPLIT {
                let expected: Vec<_> = clear_function(str, pat)
                    .map(Some)
                    .chain(once(None))
                    .collect();

                let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                let enc_rhs = GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                for rhs in [enc_rhs, clear_rhs] {
                    let mut iterator = split_executor.execute((&enc_lhs, rhs.as_ref()));

                    for expected in &expected {
                        let (split, is_some) = iterator.next(&sks);

                        let dec_split = cks.decrypt_ascii(&split);
                        let dec_is_some = cks.decrypt_bool(&is_some);

                        let dec = dec_is_some.then_some(dec_split);

                        assert_eq!(expected, &dec.as_deref())
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "aba";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["a", "c"] {
            let expected: Vec<_> = clear_function(str, rhs)
                .map(Some)
                .chain(once(None))
                .collect();

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let mut iterator = split_executor.execute((&enc_lhs, rhs.as_ref()));

                for expected in &expected {
                    let (split, is_some) = iterator.next(&sks);

                    let dec_split = cks.decrypt_ascii(&split);
                    let dec_is_some = cks.decrypt_bool(&is_some);

                    let dec = dec_is_some.then_some(dec_split);

                    assert_eq!(expected, &dec.as_deref());
                }
            }
        }
    }
}

#[test]
fn string_splitn_test_parameterized() {
    string_splitn_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_splitn_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str, u16) -> Box<dyn Iterator<Item = &'a str> + 'a>,
        fn(&ServerKey, &FheString, GenericPatternRef<'_>, UIntArg) -> Box<dyn FheStringIterator>,
    ); 2] = [
        (
            |lhs: &str, rhs: &str, n: u16| Box::new(lhs.splitn(n as usize, rhs)),
            |a, b, c, d| Box::new(ServerKey::splitn(a, b, c, d)),
        ),
        (
            |lhs: &str, rhs: &str, n: u16| Box::new(lhs.rsplitn(n as usize, rhs)),
            |a, b, c, d| Box::new(ServerKey::rsplitn(a, b, c, d)),
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_splitn_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_splitn_test_impl<P, T>(
    param: P,
    mut splitn_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str, u16) -> Box<dyn Iterator<Item = &'a str> + 'a>,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a FheString, GenericPatternRef<'a>, UIntArg),
        Box<dyn FheStringIterator>,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    splitn_executor.setup(&cks2, sks.clone());

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for (str, pat) in TEST_CASES_SPLIT {
                for n in 0..3 {
                    for max in n..n + 2 {
                        let expected: Vec<_> = clear_function(str, pat, n)
                            .map(Some)
                            .chain(once(None))
                            .collect();

                        let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                        let enc_rhs =
                            GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                        let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                        let clear_n = UIntArg::Clear(n);
                        let enc_n = UIntArg::Enc(cks.trivial_encrypt_u16(n, Some(max)));

                        for rhs in [enc_rhs, clear_rhs] {
                            for n in [clear_n.clone(), enc_n.clone()] {
                                let mut iterator =
                                    splitn_executor.execute((&enc_lhs, rhs.as_ref(), n));

                                for expected in &expected {
                                    let (split, is_some) = iterator.next(&sks);

                                    let dec_split = cks.decrypt_ascii(&split);
                                    let dec_is_some = cks.decrypt_bool(&is_some);

                                    let dec = dec_is_some.then_some(dec_split);

                                    assert_eq!(expected, &dec.as_deref())
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "aba";
        let str_pad = 1;
        let rhs_pad = 1;
        let n = 1;
        let max = 2;

        for rhs in ["a", "c"] {
            let expected: Vec<_> = clear_function(str, rhs, n)
                .map(Some)
                .chain(once(None))
                .collect();

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            let enc_n = UIntArg::Enc(cks.encrypt_u16(n, Some(max)));

            for rhs in [enc_rhs, clear_rhs] {
                let mut iterator = splitn_executor.execute((&enc_lhs, rhs.as_ref(), enc_n.clone()));

                for expected in &expected {
                    let (split, is_some) = iterator.next(&sks);

                    let dec_split = cks.decrypt_ascii(&split);
                    let dec_is_some = cks.decrypt_bool(&is_some);

                    let dec = dec_is_some.then_some(dec_split);

                    assert_eq!(expected, &dec.as_deref());
                }
            }
        }
    }
}