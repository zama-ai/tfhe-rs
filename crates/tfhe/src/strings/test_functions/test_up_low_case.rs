use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::PBSParameters;
use crate::strings::ciphertext::{ClearString, FheString, GenericPattern, GenericPatternRef};
use std::sync::Arc;

const UP_LOW_CASE: [&str; 21] = [
    "",  //
    "@", // just before 'A'
    "A", "Z", //
    "[", "\\", "]", "^", "_", "`", // chars between 'Z' and 'a'
    "a", "z", //
    "{", // just after 'z'
    "a ", " a", "A ", " A", "aA", " aA", "aA ", "a A",
];

#[test]
fn string_to_lower_upper_case_test_parameterized() {
    string_to_lower_upper_case_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_to_lower_upper_case_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str) -> String,
        fn(&ServerKey, &FheString) -> FheString,
    ); 2] = [
        (|lhs| lhs.to_lowercase(), ServerKey::to_lowercase),
        (|lhs| lhs.to_uppercase(), ServerKey::to_uppercase),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_to_lower_upper_case_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_to_lower_upper_case_test_impl<P, T>(
    param: P,
    mut to_lower_upper_case_executor: T,
    clear_function: for<'a> fn(&'a str) -> String,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a FheString, FheString>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    to_lower_upper_case_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for str in UP_LOW_CASE {
            let expected_result = clear_function(str);

            let enc_str = FheString::new(&cks, str, Some(str_pad));

            let result = to_lower_upper_case_executor.execute(&enc_str);

            assert_eq!(expected_result, cks.decrypt_ascii(&result));
        }
    }
    // encrypted
    {
        let str_pad = 1;

        for str in ["ab", "AB"] {
            let expected_result = clear_function(str);

            let enc_str = FheString::new(&cks, str, Some(str_pad));

            let result = to_lower_upper_case_executor.execute(&enc_str);

            assert_eq!(expected_result, cks.decrypt_ascii(&result));
        }
    }
}

#[test]
fn string_eq_ignore_case_test_parameterized() {
    string_eq_ignore_case_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_eq_ignore_case_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::eq_ignore_case);
    string_eq_ignore_case_test_impl(param, executor);
}

pub(crate) fn string_eq_ignore_case_test_impl<P, T>(param: P, mut eq_ignore_case_executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>), BooleanBlock>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    eq_ignore_case_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for rhs_pad in 0..2 {
            for str in UP_LOW_CASE {
                for rhs in UP_LOW_CASE {
                    let expected_result = str.eq_ignore_ascii_case(rhs);

                    let enc_str = FheString::new(&cks, str, Some(str_pad));

                    let enc_rhs =
                        GenericPattern::Enc(FheString::new_trivial(&cks, rhs, Some(rhs_pad)));
                    let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

                    for rhs in [enc_rhs, clear_rhs] {
                        let result = eq_ignore_case_executor.execute((&enc_str, rhs.as_ref()));

                        assert_eq!(expected_result, cks.decrypt_bool(&result));
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "aB";
        let str_pad = 1;
        let rhs_pad = 1;

        for rhs in ["Ab", "Ac"] {
            let expected_result = str.eq_ignore_ascii_case(rhs);

            let enc_str = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new_trivial(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let result = eq_ignore_case_executor.execute((&enc_str, rhs.as_ref()));

                assert_eq!(expected_result, cks.decrypt_bool(&result));
            }
        }
    }
}
