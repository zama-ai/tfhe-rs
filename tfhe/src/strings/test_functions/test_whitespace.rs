use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey as IntegerServerKey};
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};
use crate::strings::ciphertext::FheString;
use crate::strings::client_key::ClientKey;
use crate::strings::server_key::{split_ascii_whitespace, FheStringIterator, ServerKey};
use std::iter::once;
use std::sync::Arc;

const WHITESPACES: [&str; 5] = [" ", "\n", "\t", "\r", "\u{000C}"];

#[test]
fn trim_test_parameterized() {
    trim_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn trim_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str) -> &'a str,
        fn(&IntegerServerKey, &FheString) -> FheString,
    ); 3] = [
        (
            |lhs| lhs.trim(),
            |sk: &IntegerServerKey, str: &FheString| {
                let sk = ServerKey::new(sk);
                sk.trim(str)
            },
        ),
        (
            |lhs| lhs.trim_start(),
            |sk: &IntegerServerKey, str: &FheString| {
                let sk = ServerKey::new(sk);
                sk.trim_start(str)
            },
        ),
        (
            |lhs| lhs.trim_end(),
            |sk: &IntegerServerKey, str: &FheString| {
                let sk = ServerKey::new(sk);
                sk.trim_end(str)
            },
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        trim_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn trim_test_impl<P, T>(
    param: P,
    mut trim_executor: T,
    clear_function: for<'a> fn(&'a str) -> &'a str,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a FheString, FheString>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    trim_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);

    // trivial
    for str_pad in 0..2 {
        for ws in WHITESPACES {
            for core in ["", "a", "a a"] {
                #[allow(clippy::useless_format)]
                for str in [
                    format!("{core}"),
                    format!("{ws}{core}"),
                    format!("{core}{ws}"),
                    format!("{ws}{core}{ws}"),
                ] {
                    let expected_result = clear_function(&str);

                    let enc_str = FheString::new(&cks, &str, Some(str_pad));

                    let result = trim_executor.execute(&enc_str);

                    assert_eq!(expected_result, &cks.decrypt_ascii(&result));
                }
            }
        }
    }
    // encrypted
    {
        let str_pad = 1;

        for str in [" a ", "abc"] {
            let expected_result = clear_function(str);

            let enc_str = FheString::new(&cks, str, Some(str_pad));

            let result = trim_executor.execute(&enc_str);

            assert_eq!(expected_result, &cks.decrypt_ascii(&result));
        }
    }
}

#[test]
fn split_whitespace_test_parameterized() {
    split_whitespace_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn split_whitespace_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    #[allow(clippy::type_complexity)]
    let fhe_func: fn(
        &IntegerServerKey,
        &FheString,
    ) -> Box<dyn for<'a> FheStringIterator<&'a IntegerServerKey>> =
        |_sk, str| Box::new(split_ascii_whitespace(str));

    let executor = CpuFunctionExecutor::new(&fhe_func);

    split_whitespace_test_impl(param, executor);
}

pub(crate) fn split_whitespace_test_impl<P, T>(param: P, mut split_whitespace_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        &'a FheString,
        Box<dyn for<'b> FheStringIterator<&'b IntegerServerKey>>,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    split_whitespace_executor.setup(&cks2, sks.clone());

    let sks = ServerKey::new(&*sks);
    let cks = ClientKey::new(cks);

    // trivial
    for str_pad in 0..2 {
        for ws in WHITESPACES {
            #[allow(clippy::useless_format)]
            for str in [
                format!(""),
                format!("{ws}"),
                format!("a{ws}"),
                format!("{ws}a"),
                format!("a{ws}a"),
                format!("{ws}{ws}"),
                format!("a{ws}{ws}"),
                format!("{ws}a{ws}"),
                format!("{ws}{ws}a"),
                format!("a{ws}a{ws}"),
                format!("a{ws}{ws}a"),
                format!("{ws}a{ws}a"),
                format!("a{ws}a{ws}a"),
            ] {
                let expected: Vec<_> = str
                    .split_ascii_whitespace()
                    .map(Some)
                    .chain(once(None))
                    .collect();

                let enc_str = FheString::new(&cks, &str, Some(str_pad));

                let mut iterator = split_whitespace_executor.execute(&enc_str);

                for expected in &expected {
                    let (split, is_some) = iterator.next(&sks);

                    let dec_split = cks.decrypt_ascii(&split);
                    let dec_is_some = cks.inner().decrypt_bool(&is_some);

                    let dec = dec_is_some.then_some(dec_split);

                    assert_eq!(expected, &dec.as_deref())
                }
            }
        }
    }

    // encrypted
    {
        let str_pad = 1;

        for str in ["a b", "abc"] {
            let expected: Vec<_> = str
                .split_ascii_whitespace()
                .map(Some)
                .chain(once(None))
                .collect();

            let enc_str = FheString::new(&cks, str, Some(str_pad));

            let mut iterator = split_whitespace_executor.execute(&enc_str);

            for expected in &expected {
                let (split, is_some) = iterator.next(&sks);

                let dec_split = cks.decrypt_ascii(&split);
                let dec_is_some = cks.inner().decrypt_bool(&is_some);

                let dec = dec_is_some.then_some(dec_split);

                assert_eq!(expected, &dec.as_deref())
            }
        }
    }
}
