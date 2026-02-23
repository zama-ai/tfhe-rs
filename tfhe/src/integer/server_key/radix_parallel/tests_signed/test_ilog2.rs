use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, signed_add_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_default_trailing_zeros);
create_parameterized_test!(integer_signed_default_trailing_ones);
create_parameterized_test!(integer_signed_default_leading_zeros);
create_parameterized_test!(integer_signed_default_leading_ones);
create_parameterized_test!(integer_signed_default_ilog2);
create_parameterized_test!(integer_signed_default_checked_ilog2 {
    // uses comparison so 1_1 parameters are not supported
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    // 2M128 is too slow for 4_4, it is estimated to be 2x slower
    TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64
});

fn integer_signed_default_trailing_zeros<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::trailing_zeros_parallelized);
    default_trailing_zeros_test(param, executor);
}

fn integer_signed_default_trailing_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::trailing_ones_parallelized);
    default_trailing_ones_test(param, executor);
}

fn integer_signed_default_leading_zeros<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::leading_zeros_parallelized);
    default_leading_zeros_test(param, executor);
}

fn integer_signed_default_leading_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::leading_ones_parallelized);
    default_leading_ones_test(param, executor);
}

fn integer_signed_default_ilog2<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::ilog2_parallelized);
    default_ilog2_test(param, executor);
}

fn integer_signed_default_checked_ilog2<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::checked_ilog2_parallelized);
    default_checked_ilog2_test(param, executor);
}

pub(crate) fn signed_default_count_consecutive_bits_test<P, T>(
    direction: Direction,
    bit_value: BitValue,
    param: P,
    mut executor: T,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    let compute_expected_clear = |x: i64| match (direction, bit_value) {
        (Direction::Trailing, BitValue::Zero) => {
            if x == 0 {
                num_bits
            } else {
                x.trailing_zeros()
            }
        }
        (Direction::Trailing, BitValue::One) => x.trailing_ones().min(num_bits),
        (Direction::Leading, BitValue::Zero) => {
            if x == 0 {
                num_bits
            } else {
                (x << (u64::BITS - num_bits)).leading_zeros()
            }
        }
        (Direction::Leading, BitValue::One) => (x << (u64::BITS - num_bits)).leading_ones(),
    };

    let method_name = match (direction, bit_value) {
        (Direction::Trailing, BitValue::Zero) => "trailing_zeros",
        (Direction::Trailing, BitValue::One) => "trailing_ones",
        (Direction::Leading, BitValue::Zero) => "leading_zeros",
        (Direction::Leading, BitValue::One) => "leading_ones",
    };

    let input_values = [-modulus, 0i64, modulus - 1]
        .into_iter()
        .chain((0..nb_tests_smaller).map(|_| rng.gen::<i64>() % modulus))
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(
            ct_res, tmp,
            "Failed determinism check, \n\n\n msg: {clear}, \n\n\nctxt: {ctxt:?}\n\n\n"
        );

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = compute_expected_clear(clear);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
        );

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let clear = signed_add_under_modulus(clear, clear_2, modulus);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let ct_res = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let expected_result = compute_expected_clear(clear);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = [-modulus, 0i64, modulus - 1]
        .into_iter()
        .chain((0..nb_tests_smaller).map(|_| rng.gen::<i64>() % modulus));

    for clear in input_values {
        let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

        let ct_res = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = compute_expected_clear(clear);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
        );
    }
}

pub(crate) fn default_trailing_zeros_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    signed_default_count_consecutive_bits_test(
        Direction::Trailing,
        BitValue::Zero,
        param,
        executor,
    );
}

pub(crate) fn default_trailing_ones_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    signed_default_count_consecutive_bits_test(Direction::Trailing, BitValue::One, param, executor);
}

pub(crate) fn default_leading_zeros_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    signed_default_count_consecutive_bits_test(Direction::Leading, BitValue::Zero, param, executor);
}

pub(crate) fn default_leading_ones_test<P, T>(param: P, executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    signed_default_count_consecutive_bits_test(Direction::Leading, BitValue::One, param, executor);
}

pub(crate) fn default_ilog2_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    executor.setup(&cks, sks.clone());

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    // Test with invalid input
    {
        for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
            let ctxt = cks.encrypt_signed(clear);

            let ct_res = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = if clear < 0 {
                num_bits - 1
            } else {
                let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                    .div_ceil(cks.parameters().message_modulus().0.ilog2())
                    as usize;
                (1u32 << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                    - 1
            };
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(
            ct_res, tmp,
            "Failed determinism check, \n\n\n msg: {clear}, \n\n\nctxt: {ctxt:?}\n\n\n"
        );

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            // But here, we have to make sure clear is still > 0
            // as we are only testing valid ilog2 inputs
            let (clear, clear_2) = loop {
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear = signed_add_under_modulus(clear, clear_2, modulus);
                if clear > 0 {
                    break (clear, clear_2);
                }
            };

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let ct_res = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let expected_result = clear.ilog2();

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(
            ct_res, tmp,
            "Failed determinism check, \n\n\n msg: {clear}, \n\n\nctxt: {ctxt:?}\n\n\n"
        );

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
    }
}

pub(crate) fn default_checked_ilog2_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::rng();
    let sks = Arc::new(sks);
    executor.setup(&cks, sks.clone());

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    // Test with invalid input
    {
        for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
            let ctxt = cks.encrypt_signed(clear);

            let (ct_res, is_ok) = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = if clear < 0 {
                num_bits - 1
            } else {
                let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                    .div_ceil(cks.parameters().message_modulus().0.ilog2())
                    as usize;
                (1u32 << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                    - 1
            };
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(!is_ok);
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let (ct_res, is_ok) = executor.execute(&ctxt);
        let (tmp, tmp_is_ok) = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(
            ct_res, tmp,
            "Failed determinism check, \n\n\n msg: {clear}, \n\n\nctxt: {ctxt:?}\n\n\n"
        );
        assert_eq!(is_ok, tmp_is_ok);

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
        let is_ok = cks.decrypt_bool(&is_ok);
        assert!(is_ok);

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            // But here, we have to make sure clear is still > 0
            // as we are only testing valid ilog2 inputs
            let (clear, clear_2) = loop {
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear = signed_add_under_modulus(clear, clear_2, modulus);
                if clear > 0 {
                    break (clear, clear_2);
                }
            };

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let (ct_res, is_ok) = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(is_ok.as_ref().degree.get(), 1);

            let expected_result = clear.ilog2();

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

        let (ct_res, is_ok) = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
        let is_ok = cks.decrypt_bool(&is_ok);
        assert!(is_ok);
    }
}
