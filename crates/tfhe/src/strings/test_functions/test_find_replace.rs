use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::PBSParameters;
use crate::strings::ciphertext::{
    ClearString, FheString, GenericPattern, GenericPatternRef, UIntArg,
};
use std::sync::Arc;

const TEST_CASES_FIND: [&str; 8] = ["", "a", "abc", "b", "ab", "dabc", "abce", "dabce"];

const PATTERN_FIND: [&str; 5] = ["", "a", "b", "ab", "abc"];

#[test]
fn string_find_test_parameterized() {
    string_find_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_find_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    #[allow(clippy::type_complexity)]
    let ops: [(
        for<'a> fn(&'a str, &'a str) -> Option<usize>,
        fn(&ServerKey, &FheString, GenericPatternRef<'_>) -> (RadixCiphertext, BooleanBlock),
    ); 2] = [
        (|lhs, rhs| lhs.find(rhs), ServerKey::find),
        (|lhs, rhs| lhs.rfind(rhs), ServerKey::rfind),
    ];

    let param = param.into();

    for (clear_op, encrypted_op) in ops {
        let executor = CpuFunctionExecutor::new(&encrypted_op);
        string_find_test_impl(param, executor, clear_op);
    }
}

pub(crate) fn string_find_test_impl<P, T>(
    param: P,
    mut find_executor: T,
    clear_function: for<'a> fn(&'a str, &'a str) -> Option<usize>,
) where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a FheString, GenericPatternRef<'a>),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    find_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for pat_pad in 0..2 {
            for str in TEST_CASES_FIND {
                for pat in PATTERN_FIND {
                    let expected_result = clear_function(str, pat);

                    let enc_lhs = FheString::new_trivial(&cks, str, Some(str_pad));
                    let enc_rhs =
                        GenericPattern::Enc(FheString::new_trivial(&cks, pat, Some(pat_pad)));
                    let clear_rhs = GenericPattern::Clear(ClearString::new(pat.to_string()));

                    for rhs in [enc_rhs, clear_rhs] {
                        let (index, is_some) = find_executor.execute((&enc_lhs, rhs.as_ref()));

                        let dec_index = cks.decrypt_radix::<u32>(&index);
                        let dec_is_some = cks.decrypt_bool(&is_some);

                        let dec = dec_is_some.then_some(dec_index as usize);

                        assert_eq!(dec, expected_result);
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
            let expected_result = clear_function(str, rhs);

            let enc_lhs = FheString::new(&cks, str, Some(str_pad));
            let enc_rhs = GenericPattern::Enc(FheString::new(&cks, rhs, Some(rhs_pad)));
            let clear_rhs = GenericPattern::Clear(ClearString::new(rhs.to_string()));

            for rhs in [enc_rhs, clear_rhs] {
                let (index, is_some) = find_executor.execute((&enc_lhs, rhs.as_ref()));

                let dec_index = cks.decrypt_radix::<u32>(&index);
                let dec_is_some = cks.decrypt_bool(&is_some);

                let dec = dec_is_some.then_some(dec_index as usize);

                assert_eq!(dec, expected_result);
            }
        }
    }
}

#[test]
fn string_replace_test_parameterized() {
    string_replace_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_replace_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::replace);
    string_replace_test_impl(param, executor);
}

pub(crate) fn string_replace_test_impl<P, T>(param: P, mut replace_executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a FheString, GenericPatternRef<'a>, &'a FheString), FheString>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    replace_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for from_pad in 0..2 {
            for to_pad in 0..2 {
                for str in TEST_CASES_FIND {
                    for from in PATTERN_FIND {
                        for to in ["", " ", "a", "abc"] {
                            let expected_result = str.replace(from, to);

                            let enc_str = FheString::new_trivial(&cks, str, Some(str_pad));
                            let enc_from = GenericPattern::Enc(FheString::new_trivial(
                                &cks,
                                from,
                                Some(from_pad),
                            ));
                            let clear_from =
                                GenericPattern::Clear(ClearString::new(from.to_string()));

                            let enc_to = FheString::new_trivial(&cks, to, Some(to_pad));

                            for from in [enc_from, clear_from] {
                                let result =
                                    replace_executor.execute((&enc_str, from.as_ref(), &enc_to));

                                let dec_result = cks.decrypt_ascii(&result);

                                assert_eq!(dec_result, expected_result);
                            }
                        }
                    }
                }
            }
        }
    }
    // encrypted
    {
        let str = "ab";
        let str_pad = 1;
        let from_pad = 1;
        let to = "d";
        let to_pad = 1;

        for from in ["a", "c"] {
            let expected_result = str.replace(from, to);

            let enc_str = FheString::new_trivial(&cks, str, Some(str_pad));
            let enc_from = GenericPattern::Enc(FheString::new_trivial(&cks, from, Some(from_pad)));
            let clear_from = GenericPattern::Clear(ClearString::new(from.to_string()));

            let enc_to = FheString::new_trivial(&cks, to, Some(to_pad));

            for from in [enc_from, clear_from] {
                let result = replace_executor.execute((&enc_str, from.as_ref(), &enc_to));

                let dec_result = cks.decrypt_ascii(&result);

                assert_eq!(dec_result, expected_result);
            }
        }
    }
}

#[test]
fn string_replacen_test_parameterized() {
    string_replacen_test(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
}

#[allow(clippy::needless_pass_by_value)]
fn string_replacen_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::replacen);
    string_replacen_test_impl(param, executor);
}

pub(crate) fn string_replacen_test_impl<P, T>(param: P, mut replacen_executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a FheString,
            GenericPatternRef<'a>,
            &'a FheString,
            &'a UIntArg,
        ),
        FheString,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks2 = RadixClientKey::from((cks.clone(), 0));

    replacen_executor.setup(&cks2, sks);

    // trivial
    for str_pad in 0..2 {
        for from_pad in 0..2 {
            for to_pad in 0..2 {
                for str in TEST_CASES_FIND {
                    for from in PATTERN_FIND {
                        for to in ["", " ", "a", "abc"] {
                            for n in 0..=2 {
                                for max in n..n + 2 {
                                    let expected_result = str.replacen(from, to, n as usize);

                                    let enc_str = FheString::new_trivial(&cks, str, Some(str_pad));
                                    let enc_from = GenericPattern::Enc(FheString::new_trivial(
                                        &cks,
                                        from,
                                        Some(from_pad),
                                    ));
                                    let clear_from =
                                        GenericPattern::Clear(ClearString::new(from.to_string()));

                                    let enc_to = FheString::new_trivial(&cks, to, Some(to_pad));

                                    let clear_n = UIntArg::Clear(n);
                                    let enc_n = UIntArg::Enc(cks.trivial_encrypt_u16(n, Some(max)));

                                    for from in [enc_from, clear_from] {
                                        for n in [&clear_n, &enc_n] {
                                            let result = replacen_executor.execute((
                                                &enc_str,
                                                from.as_ref(),
                                                &enc_to,
                                                n,
                                            ));

                                            let dec_result = cks.decrypt_ascii(&result);

                                            assert_eq!(dec_result, expected_result);
                                        }
                                    }
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
        let str = "ab";
        let str_pad = 1;
        let from_pad = 1;
        let to = "d";
        let to_pad = 1;
        let n = 1;
        let max = 2;

        for from in ["a", "c"] {
            let expected_result = str.replacen(from, to, n as usize);

            let enc_str = FheString::new_trivial(&cks, str, Some(str_pad));
            let enc_from = GenericPattern::Enc(FheString::new_trivial(&cks, from, Some(from_pad)));
            let clear_from = GenericPattern::Clear(ClearString::new(from.to_string()));

            let enc_to = FheString::new_trivial(&cks, to, Some(to_pad));

            let clear_n = UIntArg::Clear(n);
            let enc_n = UIntArg::Enc(cks.encrypt_u16(n, Some(max)));

            for from in [enc_from, clear_from] {
                for n in [&clear_n, &enc_n] {
                    let result = replacen_executor.execute((&enc_str, from.as_ref(), &enc_to, n));

                    let dec_result = cks.decrypt_ascii(&result);

                    assert_eq!(dec_result, expected_result);
                }
            }
        }
    }
}
