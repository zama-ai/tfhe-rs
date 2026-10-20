use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    encrypted_shift_amount_fixed_cases, ExecuteOn, ShiftAmount, ShiftAmountOperand, TestBuilder,
    TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    signed_left_shift_under_modulus, signed_right_shift_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, panic_if_any_block_is_not_clean_or_trivial, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{
    IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_left_shift);

create_parameterized_test!(integer_signed_unchecked_right_shift);
create_parameterized_test!(integer_signed_default_left_shift);
create_parameterized_test!(integer_signed_default_right_shift);

pub(crate) fn signed_unchecked_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
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
            let shift = cks.encrypt(clear_shift as u64);

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(clear_res, dec_res);
        }

        // case when shift >= nb_bits
        {
            // The shift amount lies in [nb_bits, modulus), so it encrypts without
            // wrapping and is a genuine overshift: a left shift must return 0.
            let clear_shift = rng.gen_range(nb_bits..modulus as u32);
            let shift = cks.encrypt(clear_shift as u64);

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            assert_eq!(0, dec_res);
        }
    }
}

pub(crate) fn signed_unchecked_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
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
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            panic_if_any_block_is_not_clean_or_trivial(&ct_res, &cks);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(clear_res, dec_res);
        }

        // case when shift >= nb_bits
        {
            // The shift amount lies in [nb_bits, modulus), so it encrypts without
            // wrapping and is a genuine overshift: an arithmetic right shift
            // saturates to the sign bit (-1 if negative, 0 otherwise).
            let clear_shift = rng.gen_range(nb_bits..modulus as u32);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = if clear < 0 { -1i64 } else { 0i64 };
            assert_eq!(clear_res, dec_res);
        }
    }
}

fn integer_signed_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    signed_unchecked_right_shift_test(param, executor);
}

fn integer_signed_default_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_right_shift_test(&ctx, executor);
}

pub(crate) fn signed_default_right_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (SignedRadixCiphertext, ShiftAmountOperand<RadixCiphertext>),
        SignedRadixCiphertext,
    >,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(encrypted_shift_amount_fixed_cases::<Int>)
        .execute(
            executor,
            |(lhs, amount): (Int, ShiftAmount<RadixCiphertext>)| lhs.shr(amount.value()),
        );
}

fn integer_signed_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    signed_unchecked_left_shift_test(param, executor);
}

fn integer_signed_default_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_left_shift_test(&ctx, executor);
}

pub(crate) fn signed_default_left_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (SignedRadixCiphertext, ShiftAmountOperand<RadixCiphertext>),
        SignedRadixCiphertext,
    >,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(encrypted_shift_amount_fixed_cases::<Int>)
        .execute(
            executor,
            |(lhs, amount): (Int, ShiftAmount<RadixCiphertext>)| lhs.shl(amount.value()),
        );
}
