use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, random_non_zero_value, signed_add_under_modulus,
    NB_CTXT, NB_TESTS, NB_TESTS_UNCHECKED,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_signed_unchecked_bitand);
create_parametrized_test!(integer_signed_unchecked_bitor);
create_parametrized_test!(integer_signed_unchecked_bitxor);
create_parametrized_test!(integer_signed_default_bitnot);
create_parametrized_test!(integer_signed_default_bitand);
create_parametrized_test!(integer_signed_default_bitor);
create_parametrized_test!(integer_signed_default_bitxor);

fn integer_signed_unchecked_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitand_parallelized);
    signed_unchecked_bitand_test(param, executor);
}

fn integer_signed_unchecked_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor_parallelized);
    signed_unchecked_bitor_test(param, executor);
}

fn integer_signed_unchecked_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor_parallelized);
    signed_unchecked_bitxor_test(param, executor);
}

fn integer_signed_default_bitnot<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    signed_default_bitnot_test(param, executor);
}

fn integer_signed_default_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    signed_default_bitand_test(param, executor);
}

fn integer_signed_default_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    signed_default_bitor_test(param, executor);
}

fn integer_signed_default_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    signed_default_bitxor_test(param, executor);
}
pub(crate) fn signed_unchecked_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs::<{ NB_TESTS_UNCHECKED }>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_unchecked_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs::<{ NB_TESTS_UNCHECKED }>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_unchecked_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs::<{ NB_TESTS_UNCHECKED }>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_bitnot_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute(&ctxt_0);
        let ct_res2 = executor.execute(&ctxt_0);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = !clear_0;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let mut ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let ct_res2 = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = clear_0 & clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

pub(crate) fn signed_default_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let mut ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let ct_res2 = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = clear_0 | clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

pub(crate) fn signed_default_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let mut ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let ct_res2 = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed(&ct_res);

        let expected_result = clear_0 ^ clear_1;
        assert_eq!(dec_res, expected_result);
    }
}
