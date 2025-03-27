use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NotTuple};
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey as IntegerServerKey};
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern, GenericPatternRef};
use crate::strings::client_key::ClientKey;
use crate::strings::server_key::{FheStringIsEmpty, FheStringLen, ServerKey};
use std::sync::Arc;

#[test]
fn test_encrypt_decrypt_parameterized() {
    test_encrypt_decrypt(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

fn test_encrypt_decrypt<P>(param: P)
where
    P: Into<TestParameters>,
{
    let (cks, _sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let cks = ClientKey::new(cks);

    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            let enc_str = FheString::new(&cks, str, Some(pad));

            let dec = cks.decrypt_ascii(&enc_str);

            assert_eq!(str, &dec);
        }
    }
}

#[test]
fn is_empty_test_parameterized() {
    is_empty_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

impl NotTuple for &FheString {}

#[allow(clippy::needless_pass_by_value)]
fn is_empty_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&|sk: &IntegerServerKey, str: &FheString| {
        let sk = ServerKey::new(sk);
        sk.is_empty(str)
    });
    is_empty_test_impl(param, executor);
}

pub(crate) fn is_empty_test_impl<P, T>(param: P, mut is_empty_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a FheString, FheStringIsEmpty>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    is_empty_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);

    // trivial
    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            let expected_result = str.is_empty();

            let enc_str = FheString::new_trivial(&cks, str, Some(pad));

            let result = is_empty_executor.execute(&enc_str);

            match result {
                FheStringIsEmpty::NoPadding(result) => assert_eq!(result, expected_result),
                FheStringIsEmpty::Padding(result) => {
                    assert_eq!(cks.inner().decrypt_bool(&result), expected_result)
                }
            }
        }
    }
    // encrypted
    {
        let pad = 1;

        for str in ["", "abc"] {
            let expected_result = str.is_empty();

            let enc_str = FheString::new(&cks, str, Some(pad));

            let result = is_empty_executor.execute(&enc_str);

            match result {
                FheStringIsEmpty::NoPadding(result) => assert_eq!(result, expected_result),
                FheStringIsEmpty::Padding(result) => {
                    assert_eq!(cks.inner().decrypt_bool(&result), expected_result)
                }
            }
        }
    }
}

#[test]
fn len_test_parameterized() {
    len_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn len_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&|sk: &IntegerServerKey, str: &FheString| {
        let sk = ServerKey::new(sk);
        sk.len(str)
    });
    len_test_impl(param, executor);
}

pub(crate) fn len_test_impl<P, T>(param: P, mut len_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a FheString, FheStringLen>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    len_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);

    // trivial
    for str in ["", "a", "abc"] {
        for pad in 0..3 {
            let expected_result = str.len();

            let enc_str = FheString::new_trivial(&cks, str, Some(pad));

            let result = len_executor.execute(&enc_str);

            match result {
                FheStringLen::NoPadding(result) => {
                    assert_eq!(result, expected_result)
                }
                FheStringLen::Padding(result) => {
                    assert_eq!(
                        cks.inner().decrypt_radix::<u16>(&result),
                        expected_result as u16
                    )
                }
            }
        }
    }
    // encrypted
    {
        let pad = 1;

        for str in ["", "abc"] {
            let expected_result = str.len();

            let enc_str = FheString::new(&cks, str, Some(pad));

            let result = len_executor.execute(&enc_str);

            match result {
                FheStringLen::NoPadding(result) => {
                    assert_eq!(result, expected_result)
                }
                FheStringLen::Padding(result) => {
                    assert_eq!(
                        cks.inner().decrypt_radix::<u64>(&result),
                        expected_result as u64
                    )
                }
            }
        }
    }
}

#[test]
fn strip_test_parameterized() {
    strip_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn strip_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> Option<&'a str>,
        fn(
            &ServerKey<&IntegerServerKey>,
            &FheString,
            GenericPatternRef<'_>,
        ) -> (FheString, BooleanBlock),
    ); 2] = [
        (
            |lhs, rhs| lhs.strip_prefix(rhs),
            |sk, str, pat| sk.strip_prefix(str, pat),
        ),
        (
            |lhs, rhs| lhs.strip_suffix(rhs),
            |sk, str, pat| sk.strip_suffix(str, pat),
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let encrypted_op_wrapper =
            |sk: &IntegerServerKey, str: &FheString, pat: GenericPatternRef<'_>| {
                let sk = ServerKey::new(sk);
                encrypted_op(&sk, str, pat)
            };
        let executor = CpuFunctionExecutor::new(&encrypted_op_wrapper);
        strip_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn strip_test_impl<P, T>(
    param: P,
    mut strip_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> Option<&'a str>,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), (FheString, BooleanBlock)>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    strip_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);

    let assert_result = |expected_result: (&str, bool), result: (FheString, BooleanBlock)| {
        assert_eq!(expected_result.1, cks.inner().decrypt_bool(&result.1));

        assert_eq!(expected_result.0, cks.decrypt_ascii(&result.0));
    };

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for pat in ["", "a", "abc"] {
                for str in ["", "a", "abc", "b", "ab", "dddabc", "abceeee", "dddabceee"] {
                    let expected_result =
                        clear_function(str, pat).map_or((str, false), |str| (str, true));

                    let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                    let enc_rhs =
                        GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                    let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                    for rhs in [enc_rhs, clear_rhs] {
                        let result = strip_executor.execute((&enc_lhs, rhs.as_ref()));

                        assert_result(expected_result, result);
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "abc";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["a", "c", "d"] {
            let expected_result = clear_function(str, rhs).map_or((str, false), |str| (str, true));

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let result = strip_executor.execute((&enc_lhs, rhs.as_ref()));

                assert_result(expected_result, result);
            }
        }
    }
}

const TEST_CASES_COMP: [&str; 5] = ["", "a", "aa", "ab", "abc"];

#[test]
fn comp_test_parameterized() {
    comp_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn comp_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        fn(&str, &str) -> bool,
        fn(&ServerKey<&IntegerServerKey>, &FheString, GenericPatternRef<'_>) -> BooleanBlock,
    ); 6] = [
        (|lhs, rhs| lhs == rhs, |sk, lhs, rhs| sk.eq(lhs, rhs)),
        (|lhs, rhs| lhs != rhs, |sk, lhs, rhs| sk.ne(lhs, rhs)),
        (|lhs, rhs| lhs >= rhs, |sk, lhs, rhs| sk.ge(lhs, rhs)),
        (|lhs, rhs| lhs <= rhs, |sk, lhs, rhs| sk.le(lhs, rhs)),
        (|lhs, rhs| lhs > rhs, |sk, lhs, rhs| sk.gt(lhs, rhs)),
        (|lhs, rhs| lhs < rhs, |sk, lhs, rhs| sk.lt(lhs, rhs)),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let encrypted_op_wrapper =
            |sk: &IntegerServerKey, lhs: &FheString, rhs: GenericPatternRef<'_>| {
                let sk = ServerKey::new(sk);
                encrypted_op(&sk, lhs, rhs)
            };
        let executor = CpuFunctionExecutor::new(&encrypted_op_wrapper);
        comp_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn comp_test_impl<P, T>(
    param: P,
    mut comp_executor: T,
    clear_function: fn(&str, &str) -> bool,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), BooleanBlock>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    let cks = ClientKey::new(cks);

    let assert_result = |expected_result, result: BooleanBlock| {
        let dec_result = cks.inner().decrypt_bool(&result);

        assert_eq!(dec_result, expected_result);
    };

    comp_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in TEST_CASES_COMP {
                for rhs in TEST_CASES_COMP {
                    let expected_result = clear_function(str, rhs);

                    let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                    let enc_rhs =
                        GenericPattern::Enc(FheString::new_trivial(&cks, rhs, Some(rhs_pad)));
                    let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

                    for rhs in [enc_rhs, clear_rhs] {
                        let result = comp_executor.execute((&enc_lhs, rhs.as_ref()));

                        assert_result(expected_result, result);
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "a";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["a", "b"] {
            let expected_result = clear_function(str, rhs);

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let result = comp_executor.execute((&enc_lhs, rhs.as_ref()));

                assert_result(expected_result, result);
            }
        }
    }
}
