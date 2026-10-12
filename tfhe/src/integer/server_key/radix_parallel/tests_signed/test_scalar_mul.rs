use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{signed_mul_under_modulus, NB_CTXT};
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

create_parameterized_test!(integer_signed_unchecked_scalar_mul);
create_parameterized_test!(integer_signed_unchecked_scalar_mul_corner_cases);

fn integer_signed_unchecked_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_mul_parallelized);
    signed_unchecked_scalar_mul_test(param, executor);
}

fn integer_signed_unchecked_scalar_mul_corner_cases<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_mul_parallelized);
    signed_unchecked_scalar_mul_corner_cases_test(param, executor);
}

pub(crate) fn signed_unchecked_scalar_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_mul_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_unchecked_scalar_mul_corner_cases_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    let clear = 11i64 % modulus;

    // i64::MIN is a negative power of two: it must take the
    // bit-decomposition path and all its set bits are out of the
    // ciphertext range, -4 is a small negative power of two,
    // -1 exercises full sign extension
    for scalar in [0i64, 1, -1, 4, -4, i64::MIN] {
        let ctxt = cks.encrypt_signed(clear);
        let ct_res = executor.execute((&ctxt, scalar));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_mul_under_modulus(clear, scalar, modulus);
        assert_eq!(
            clear_res, dec_res,
            "Invalid result for {clear} * {scalar}, expected {clear_res}, got {dec_res}"
        );
    }

    // Multiplying by zero must give a clean trivial zero,
    // even when the input has non-empty carries
    let ctxt = cks.encrypt_signed(clear);
    let ctxt = sks.unchecked_add(&ctxt, &ctxt);
    assert!(!ctxt.block_carries_are_empty());

    let ct_res = executor.execute((&ctxt, 0i64));
    let dec_res: i64 = cks.decrypt_signed(&ct_res);
    assert_eq!(dec_res, 0);
    assert!(ct_res.block_carries_are_empty());
    assert!(ct_res.blocks.iter().all(|block| block.degree.get() == 0));
}
