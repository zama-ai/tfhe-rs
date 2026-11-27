use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    encrypted_rotation_amount_fixed_cases, ExecuteOn, ShiftAmount, ShiftAmountOperand, TestBuilder,
    TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_shift::amount_of_another_width_test;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, rotate_left_helper, rotate_right_helper, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_rotate_right);

create_parameterized_test!(integer_unchecked_rotate_left);

create_parameterized_test!(integer_default_rotate_right);

create_parameterized_test!(integer_default_rotate_left);

create_parameterized_test!(integer_rotate_left_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
});

create_parameterized_test!(integer_rotate_right_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
});

fn integer_rotate_left_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    rotate_left_amount_of_another_width_test(param, executor);
}

fn integer_rotate_right_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    rotate_right_amount_of_another_width_test(param, executor);
}

pub(crate) fn rotate_left_amount_of_another_width_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    amount_of_another_width_test(param, executor, |value, amount, nb_bits| {
        rotate_left_helper(value, (amount % u64::from(nb_bits)) as u32, nb_bits)
    });
}

pub(crate) fn rotate_right_amount_of_another_width_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    amount_of_another_width_test(param, executor, |value, amount, nb_bits| {
        rotate_right_helper(value, (amount % u64::from(nb_bits)) as u32, nb_bits)
    });
}

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    unchecked_rotate_right_test(param, executor);
}

fn integer_default_rotate_right<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_rotate_right_test(&ctx, executor);
}

pub(crate) fn default_rotate_right_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<RadixCiphertext>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(encrypted_rotation_amount_fixed_cases::<Uint>)
        .execute(
            executor,
            |(lhs, amount): (Uint, ShiftAmount<RadixCiphertext>)| lhs.rotate_right(amount.value()),
        );
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    unchecked_rotate_left_test(param, executor);
}

fn integer_default_rotate_left<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_rotate_left_test(&ctx, executor);
}

pub(crate) fn default_rotate_left_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<RadixCiphertext>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(encrypted_rotation_amount_fixed_cases::<Uint>)
        .execute(
            executor,
            |(lhs, amount): (Uint, ShiftAmount<RadixCiphertext>)| lhs.rotate_left(amount.value()),
        );
}

pub(crate) fn unchecked_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_rotate = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_left_helper(clear, clear_rotate, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_rotate = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            // The amount is encrypted on the radix, i.e. reduced modulo 2^nb_bits, and the
            // rotation then reduces it modulo nb_bits
            let encrypted_amount = (u64::from(clear_rotate) % modulus) as u32;
            let expected = rotate_left_helper(clear, encrypted_amount, nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}

pub(crate) fn unchecked_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_rotate = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_right_helper(clear, clear_rotate, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_rotate = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            // The amount is encrypted on the radix, i.e. reduced modulo 2^nb_bits, and the
            // rotation then reduces it modulo nb_bits
            let encrypted_amount = (u64::from(clear_rotate) % modulus) as u32;
            let expected = rotate_right_helper(clear, encrypted_amount, nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}
