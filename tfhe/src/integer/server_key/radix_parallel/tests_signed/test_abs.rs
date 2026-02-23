use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    absolute_value_under_modulus, signed_add_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_default_absolute_value);
create_parameterized_test!(integer_signed_unchecked_absolute_value);
create_parameterized_test!(integer_signed_smart_absolute_value);

fn integer_signed_default_absolute_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::abs_parallelized);
    signed_default_absolute_value_test(param, executor);
}

fn integer_signed_unchecked_absolute_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_abs_parallelized);
    signed_unchecked_absolute_value_test(param, executor);
}

fn integer_signed_smart_absolute_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_abs_parallelized);
    signed_smart_absolute_value_test(param, executor);
}

pub(crate) fn signed_unchecked_absolute_value_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // For signed integers, the range of value is [-modulus..modulus[
    // e.g.: for i8, the range is [-128..128[ <=> [-128..127]
    // which means -modulus cannot be represented.
    //
    // In Rust, .abs() / .wrapping_abs() returns MIN (-modulus)
    // https://doc.rust-lang.org/std/primitive.i8.html#method.wrapping_abs
    //
    // Here we test we have same behaviour
    //
    // (Conveniently, when using Two's complement, casting the result of abs to
    // an unsigned to will give correct value for -modulus
    // e.g.:(-128i8).wrapping_abs() as u8 == 128
    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_smart_absolute_value_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a mut SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks.clone());

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    {
        let clear_0 = -modulus;
        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute(&mut ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..nb_tests {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = executor.execute(&mut ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_absolute_value_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks.clone());

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..nb_tests {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = executor.execute(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);

        let ct_res2 = executor.execute(&ctxt_0);
        assert_eq!(ct_res2, ct_res);
    }
}
