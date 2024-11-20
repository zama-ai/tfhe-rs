use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::PBSParameters;
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern, GenericPatternRef};
use std::sync::Arc;

#[test]
fn string_contains_test_parameterized() {
    string_contains_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_contains_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> bool,
        fn(&ServerKey, &FheString, GenericPatternRef<'_>) -> BooleanBlock,
    ); 3] = [
        (|lhs, rhs| lhs.contains(rhs), ServerKey::contains),
        (|lhs, rhs| lhs.starts_with(rhs), ServerKey::starts_with),
        (|lhs, rhs| lhs.ends_with(rhs), ServerKey::ends_with),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_contains_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_contains_test_impl<P, T>(
    param: P,
    mut contains_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> bool,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), BooleanBlock>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    contains_executor.setup(&cks2, sks);

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

                        assert_eq!(expected_result, cks.decrypt_bool(&result));
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

                assert_eq!(expected_result, cks.decrypt_bool(&result));
            }
        }
    }
}
