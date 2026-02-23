use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, signed_add_under_modulus, NB_CTXT,
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

create_parameterized_test!(integer_signed_default_scalar_bitand);
create_parameterized_test!(integer_signed_default_scalar_bitor);
create_parameterized_test!(integer_signed_default_scalar_bitxor);

fn integer_signed_default_scalar_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    signed_default_scalar_bitand_test(param, executor);
}

fn integer_signed_default_scalar_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    signed_default_scalar_bitor_test(param, executor);
}

fn integer_signed_default_scalar_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    signed_default_scalar_bitxor_test(param, executor);
}
pub(crate) fn signed_default_scalar_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let ct_res2 = executor.execute((&ctxt_0, clear_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) & clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

pub(crate) fn signed_default_scalar_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let ct_res2 = executor.execute((&ctxt_0, clear_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) | clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

pub(crate) fn signed_default_scalar_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let ct_res2 = executor.execute((&ctxt_0, clear_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) ^ clear_1;
        assert_eq!(dec_res, expected_result);
    }
}
