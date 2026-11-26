use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    encrypted_shift_amount_fixed_cases, ExecuteOn, ShiftAmount, ShiftAmountOperand, TestBuilder,
    TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_left_shift);
create_parameterized_test!(integer_unchecked_right_shift);
create_parameterized_test!(integer_default_left_shift);
create_parameterized_test!(integer_default_right_shift);
create_parameterized_test!(integer_left_shift_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
});
create_parameterized_test!(integer_right_shift_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
});

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    unchecked_left_shift_test(param, executor);
}

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    unchecked_right_shift_test(param, executor);
}

fn integer_default_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_right_shift_test(&ctx, executor);
}

pub(crate) fn default_right_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<RadixCiphertext>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(encrypted_shift_amount_fixed_cases::<Uint>)
        .execute(
            executor,
            |(lhs, amount): (Uint, ShiftAmount<RadixCiphertext>)| lhs.shr(amount.value()),
        );
}

fn integer_default_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_left_shift_test(&ctx, executor);
}

pub(crate) fn default_left_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<RadixCiphertext>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(encrypted_shift_amount_fixed_cases::<Uint>)
        .execute(
            executor,
            |(lhs, amount): (Uint, ShiftAmount<RadixCiphertext>)| lhs.shl(amount.value()),
        );
}

fn integer_left_shift_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    left_shift_amount_of_another_width_test(param, executor);
}

fn integer_right_shift_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    right_shift_amount_of_another_width_test(param, executor);
}

pub(crate) fn left_shift_amount_of_another_width_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    amount_of_another_width_test(param, executor, |value, amount, nb_bits| {
        if amount >= u64::from(nb_bits) {
            0
        } else {
            (value << amount) & ((1 << nb_bits) - 1)
        }
    });
}

pub(crate) fn right_shift_amount_of_another_width_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    amount_of_another_width_test(param, executor, |value, amount, nb_bits| {
        if amount >= u64::from(nb_bits) {
            0
        } else {
            value >> amount
        }
    });
}

/// `clear_op` takes the value, the amount and the number of bits of the value.
pub(crate) fn amount_of_another_width_test<P, T>(
    param: P,
    mut executor: T,
    clear_op: impl Fn(u64, u64, u32) -> u64,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    executor.setup(&cks, sks);

    let message_modulus = cks.parameters().message_modulus().0;
    let bits_per_block = message_modulus.ilog2();
    // (value, value blocks, amount, amount blocks)
    let cases = [
        (200u64, 4usize, 3u64, 8usize),
        (200, 4, 300, 8),
        (200, 4, 3, 1),
        (200, 4, 13, 2),
        (2, 1, 1, 4),
        (3, 1, 17, 4),
    ];

    for (value, value_blocks, amount, amount_blocks) in cases {
        let value = value % message_modulus.pow(value_blocks as u32);
        let amount = amount % message_modulus.pow(amount_blocks as u32);
        let ct = cks.as_ref().encrypt_radix(value, value_blocks);
        let ct_amount = cks.as_ref().encrypt_radix(amount, amount_blocks);

        let encrypted_result = executor.execute((&ct, &ct_amount));
        assert_eq!(encrypted_result.blocks.len(), value_blocks);
        let decrypted_result: u64 = cks.as_ref().decrypt_radix(&encrypted_result);

        let nb_bits = bits_per_block * value_blocks as u32;
        assert_eq!(
            decrypted_result,
            clear_op(value, amount, nb_bits),
            "{value} on {value_blocks} blocks by {amount} on {amount_blocks} blocks"
        );
    }
}

pub(crate) fn unchecked_left_shift_test<P, T>(param: P, mut executor: T)
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

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);

            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!((clear << clear_shift) % modulus, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            // The shift amount lies in [nb_bits, modulus), so it encrypts without
            // wrapping and is a genuine overshift: the result must be 0.
            let clear_shift = rng.gen_range(nb_bits..modulus as u32);
            let shift = cks.encrypt(clear_shift as u64);

            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!(0, decrypted_result);
        }
    }
}

pub(crate) fn unchecked_right_shift_test<P, T>(param: P, mut executor: T)
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

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!((clear >> clear_shift) % modulus, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            // The shift amount lies in [nb_bits, modulus), so it encrypts without
            // wrapping and is a genuine overshift: the result must be 0.
            let clear_shift = rng.gen_range(nb_bits..modulus as u32);
            let shift = cks.encrypt(clear_shift as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!(0, decrypted_result);
        }
    }
}
