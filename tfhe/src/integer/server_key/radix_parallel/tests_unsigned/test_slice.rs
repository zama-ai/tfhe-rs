use std::ops::{Range, RangeBounds};
use std::sync::Arc;

use rand::prelude::*;

use crate::error::InvalidRangeError;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix::slice::normalize_range;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    overflowing_add_under_modulus, random_non_zero_value,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::prelude::CastFrom;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

use super::{nb_tests_for_params, CpuFunctionExecutor, FunctionExecutor, NB_CTXT};

create_parameterized_test!(integer_unchecked_scalar_slice);
create_parameterized_test!(integer_unchecked_scalar_slice_assign);
create_parameterized_test!(integer_default_scalar_slice);
create_parameterized_test!(integer_default_scalar_slice_assign);
create_parameterized_test!(integer_smart_scalar_slice);
create_parameterized_test!(integer_smart_scalar_slice_assign);

// Reference implementation of the slice
fn slice_reference_impl<B, R>(value: u64, range: R, modulus: u64) -> u64
where
    R: RangeBounds<B>,
    B: CastFrom<usize> + Copy,
    usize: CastFrom<B>,
{
    let range = normalize_range(&range, modulus.ilog2() as usize).unwrap();
    let bin: String = format!("{value:064b}").chars().rev().collect();

    let out_bin: String = bin[range].chars().rev().collect();
    u64::from_str_radix(&out_bin, 2).unwrap_or_default()
}

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn scalar_blockslice_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, Range<usize>),
        Result<RadixCiphertext, InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<usize>() % NB_CTXT;
        let range_b = rng.gen::<usize>() % NB_CTXT;

        let (block_start, block_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let bit_start = block_start * (param.message_modulus().0.ilog2() as usize);
        let bit_end = block_end * (param.message_modulus().0.ilog2() as usize);

        let ct = cks.encrypt(clear);

        let ct_res = executor.execute((&ct, block_start..block_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            slice_reference_impl(clear, bit_start..bit_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn scalar_blockslice_assign_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, usize, usize), ()>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % (NB_CTXT as u32);
        let range_b = rng.gen::<u32>() % (NB_CTXT as u32);

        let (block_start, block_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let bit_start = block_start * param.message_modulus().0.ilog2();
        let bit_end = block_end * param.message_modulus().0.ilog2();

        let mut ct = cks.encrypt(clear);

        executor.execute((&mut ct, block_start as usize, block_end as usize));
        let dec_res: u64 = cks.decrypt(&ct);
        assert_eq!(
            slice_reference_impl(clear, bit_start..bit_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn unchecked_scalar_bitslice_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, Range<u32>),
        Result<RadixCiphertext, InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let ct = cks.encrypt(clear);

        let ct_res = executor.execute((&ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn unchecked_scalar_bitslice_assign_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, Range<u32>),
        Result<(), InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let mut ct = cks.encrypt(clear);

        executor.execute((&mut ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn default_scalar_bitslice_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, Range<u32>),
        Result<RadixCiphertext, InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let mut ct = cks.encrypt(clear);

        let offset = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ct, offset);

        let (clear, _) = overflowing_add_under_modulus(clear, offset, modulus);

        let ct_res = executor.execute((&ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn default_scalar_bitslice_assign_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, Range<u32>),
        Result<(), InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let mut ct = cks.encrypt(clear);

        let offset = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ct, offset);

        let (clear, _) = overflowing_add_under_modulus(clear, offset, modulus);

        executor.execute((&mut ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn smart_scalar_bitslice_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, Range<u32>),
        Result<RadixCiphertext, InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let mut ct = cks.encrypt(clear);

        let offset = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ct, offset);

        let (clear, _) = overflowing_add_under_modulus(clear, offset, modulus);

        let ct_res = executor.execute((&mut ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

pub(crate) fn smart_scalar_bitslice_assign_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, Range<u32>),
        Result<(), InvalidRangeError>,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let range_a = rng.gen::<u32>() % modulus.ilog2();
        let range_b = rng.gen::<u32>() % modulus.ilog2();

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let mut ct = cks.encrypt(clear);

        let offset = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ct, offset);

        let (clear, _) = overflowing_add_under_modulus(clear, offset, modulus);

        executor.execute((&mut ct, range_start..range_end)).unwrap();
        let dec_res: u64 = cks.decrypt(&ct);
        assert_eq!(
            slice_reference_impl(clear, range_start..range_end, modulus),
            dec_res,
        );
    }
}

fn integer_unchecked_scalar_slice<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_bitslice_parallelized);
    unchecked_scalar_bitslice_test(param, executor);
}

fn integer_unchecked_scalar_slice_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_bitslice_assign_parallelized);
    unchecked_scalar_bitslice_assign_test(param, executor);
}

fn integer_default_scalar_slice<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitslice_parallelized);
    default_scalar_bitslice_test(param, executor);
}

fn integer_default_scalar_slice_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitslice_assign_parallelized);
    default_scalar_bitslice_assign_test(param, executor);
}

fn integer_smart_scalar_slice<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_bitslice_parallelized);
    smart_scalar_bitslice_test(param, executor);
}

fn integer_smart_scalar_slice_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_bitslice_assign_parallelized);
    smart_scalar_bitslice_assign_test(param, executor);
}
