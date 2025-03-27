use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey as IntegerServerKey};
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};
use crate::strings::ciphertext::{FheString, UIntArg};
use crate::strings::client_key::ClientKey;
use crate::strings::server_key::ServerKey;
use std::sync::Arc;

const TEST_CASES_CONCAT: [&str; 5] = ["", "a", "ab", "abc", "abcd"];

#[test]
fn concat_test_parameterized() {
    concat_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn concat_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&|sk: &IntegerServerKey, in1: &FheString, in2: &FheString| {
            let sk = ServerKey::new(sk);
            sk.concat(in1, in2)
        });
    concat_test_impl(param, executor);
}

pub(crate) fn concat_test_impl<P, T>(param: P, mut concat_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, &'a FheString), FheString>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    concat_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);
    // trivial
    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in TEST_CASES_CONCAT {
                for rhs in TEST_CASES_CONCAT {
                    let expected_result = str.to_owned() + rhs;

                    let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                    let enc_rhs = FheString::new_trivial(&cks, rhs, Some(rhs_pad));

                    let result = concat_executor.execute((&enc_lhs, &enc_rhs));

                    assert_eq!(expected_result, cks.decrypt_ascii(&result));
                }
            }
        }
    }
    // encrypted
    {
        let str = "a";
        let str_pad = 1;
        let rhs = "b";
        let rhs_pad = 1;

        let expected_result = str.to_owned() + rhs;

        let enc_lhs = FheString::new(&cks, str, Some(str_pad));
        let enc_rhs = FheString::new(&cks, rhs, Some(rhs_pad));

        let result = concat_executor.execute((&enc_lhs, &enc_rhs));

        assert_eq!(expected_result, cks.decrypt_ascii(&result));
    }
}

#[test]
fn repeat_test_parameterized() {
    repeat_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn repeat_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&|sk: &IntegerServerKey, str: &FheString, n: &UIntArg| {
            let sk = ServerKey::new(sk);
            sk.repeat(str, n)
        });
    repeat_test_impl(param, executor);
}

pub(crate) fn repeat_test_impl<P, T>(param: P, mut repeat_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, &'a UIntArg), FheString>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    repeat_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);
    // trivial
    for str_pad in 0..2 {
        for n in 0..3 {
            for str in TEST_CASES_CONCAT {
                for max in n..n + 2 {
                    let expected_result = str.repeat(n as usize);

                    let enc_str = FheString::new_trivial(&cks, str, Some(str_pad));

                    let enc_n = UIntArg::Enc(cks.trivial_encrypt_u16(n, Some(max)));

                    let clear_n = UIntArg::Clear(n);

                    for n in [clear_n, enc_n] {
                        let result = repeat_executor.execute((&enc_str, &n));

                        assert_eq!(expected_result, cks.decrypt_ascii(&result));
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "a";
        let str_pad = 1;
        let n = 1;
        let max = 2;

        let expected_result = str.repeat(n as usize);

        let enc_str = FheString::new(&cks, str, Some(str_pad));

        let enc_n = UIntArg::Enc(cks.encrypt_u16(n, Some(max)));

        let clear_n = UIntArg::Clear(n);

        for n in [clear_n, enc_n] {
            let result = repeat_executor.execute((&enc_str, &n));

            assert_eq!(expected_result, cks.decrypt_ascii(&result));
        }
    }
}
