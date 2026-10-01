use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    shift_amount_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    signed_left_shift_under_modulus, signed_right_shift_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_scalar_left_shift);
create_parameterized_test!(integer_signed_default_scalar_left_shift);
create_parameterized_test!(integer_signed_unchecked_scalar_right_shift);
create_parameterized_test!(integer_signed_default_scalar_right_shift);

fn integer_signed_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    signed_unchecked_scalar_left_shift_test(param, executor);
}

fn integer_signed_default_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_left_shift_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_left_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, u128), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(shift_amount_fixed_cases::<Int>)
        .execute(executor, |(lhs, amount): (Int, TestScalar<u128>)| {
            lhs.shl(amount.clear().value())
        });
}

fn integer_signed_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    signed_unchecked_scalar_right_shift_test(param, executor);
}

fn integer_signed_default_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_right_shift_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_right_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, u128), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(shift_amount_fixed_cases::<Int>)
        .execute(executor, |(lhs, amount): (Int, TestScalar<u128>)| {
            lhs.shr(amount.clear().value())
        });
}
pub(crate) fn signed_unchecked_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            // An overshift pushes every bit out, so a left shift returns 0.
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            assert_eq!(0, dec_res);
        }
    }
}

pub(crate) fn signed_unchecked_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            // An overshift saturates an arithmetic right shift to the sign: -1 if negative, else 0.
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = if clear < 0 { -1i64 } else { 0i64 };
            assert_eq!(expected, dec_res);
        }
    }
}
