use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, rotate_left_helper, rotate_right_helper, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_scalar_rotate_left);
create_parameterized_test!(integer_default_scalar_rotate_left);
create_parameterized_test!(integer_unchecked_scalar_rotate_right);
create_parameterized_test!(integer_default_scalar_rotate_right);

fn integer_default_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    default_scalar_rotate_left_test(param, executor);
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_left_parallelized);
    unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_default_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    default_scalar_rotate_right_test(param, executor);
}

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_right_parallelized);
    unchecked_scalar_rotate_right_test(param, executor);
}

pub(crate) fn unchecked_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..(nb_tests / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.leading_zeros() + rng.gen_range(1..nb_bits);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}

pub(crate) fn unchecked_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..(nb_tests / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.trailing_zeros() + rng.gen_range(1..nb_bits);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}

pub(crate) fn default_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for _ in 0..(nb_tests / 2).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.trailing_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_right_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

pub(crate) fn default_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..(nb_tests / 3).max(1) {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // Force case where n is multiple of block size
        {
            let scalar = scalar - (scalar % bits_per_block);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where n is not multiple of block size
        {
            let rest = scalar % bits_per_block;
            let scalar = if rest == 0 {
                scalar + (rng.gen::<u32>() % bits_per_block)
            } else {
                scalar
            };
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // Force case where
        // The value is non zero
        // we rotate so that at least one non zero bit, cycle/wraps around
        {
            let value = rng.gen_range(1..=u32::MAX);
            let scalar = value.leading_zeros() + rng.gen_range(1..nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            let expected = rotate_left_helper(clear, scalar, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}
