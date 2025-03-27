use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey as IntegerServerKey};
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern, GenericPatternRef};
use crate::strings::client_key::ClientKey;
use crate::strings::server_key::ServerKey;
use std::sync::Arc;

#[test]
fn contains_test_parameterized() {
    contains_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
}

#[allow(clippy::needless_pass_by_value)]
fn contains_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> bool,
        fn(&IntegerServerKey, &FheString, GenericPatternRef<'_>) -> BooleanBlock,
    ); 3] = [
        (
            |lhs, rhs| lhs.contains(rhs),
            |sk, lhs, rhs| {
                let sk = ServerKey::new(sk);
                sk.contains(lhs, rhs)
            },
        ),
        (
            |lhs, rhs| lhs.starts_with(rhs),
            |sk, lhs, rhs| {
                let sk = ServerKey::new(sk);
                sk.starts_with(lhs, rhs)
            },
        ),
        (
            |lhs, rhs| lhs.ends_with(rhs),
            |sk, lhs, rhs| {
                let sk = ServerKey::new(sk);
                sk.ends_with(lhs, rhs)
            },
        ),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        contains_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn contains_test_impl<P, T>(
    param: P,
    mut contains_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> bool,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), BooleanBlock>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    contains_executor.setup(&cks2, sks);

    let cks = ClientKey::new(cks);

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for str in ["", "a", "abc", "b", "ab", "dddabc", "abceeee", "dddabceee"] {
                for pat in ["", "a", "abc"] {
                    let expected_result = clear_function(str, pat);

                    let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                    let enc_rhs =
                        GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                    let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                    for rhs in [enc_rhs, clear_rhs] {
                        let result = contains_executor.execute((&enc_lhs, rhs.as_ref()));

                        assert_eq!(expected_result, cks.inner().decrypt_bool(&result));
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "ab";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["a", "b", "c"] {
            let expected_result = clear_function(str, rhs);

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let result = contains_executor.execute((&enc_lhs, rhs.as_ref()));

                assert_eq!(expected_result, cks.inner().decrypt_bool(&result));
            }
        }
    }
}
