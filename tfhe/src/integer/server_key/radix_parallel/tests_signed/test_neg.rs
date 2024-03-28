use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, signed_neg_under_modulus, NB_CTXT, NB_TESTS_SMALLER,
    NB_TESTS_UNCHECKED,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_signed_unchecked_neg);
create_parametrized_test!(integer_signed_smart_neg);
create_parametrized_test!(integer_signed_default_neg);

fn integer_signed_unchecked_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_neg);
    signed_unchecked_neg_test(param, executor);
}

fn integer_signed_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    signed_smart_neg_test(param, executor);
}

fn integer_signed_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    signed_default_neg_test(param, executor);
}

pub(crate) fn signed_unchecked_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let ctxt_zero = sks.create_trivial_radix(0i64, NB_CTXT);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // -modulus is a special case, its negation cannot be
    // represented. rust by default returns -modulus
    // (which is what two complement result in)
    {
        let clear = -modulus;
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = executor.execute(&ctxt);

        let dec: i64 = cks.decrypt_signed(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
        assert_eq!(clear_result, -modulus);
    }

    for (clear_0, _) in
        create_iterator_of_signed_random_pairs::<{ NB_TESTS_UNCHECKED }>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_neg_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }

    // negation of trivial 0
    {
        let ct_res = executor.execute(&ctxt_zero);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(0, dec_res);
    }
}

pub(crate) fn signed_smart_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a mut SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<i64>() % modulus;

        let mut ctxt = cks.encrypt_signed(clear);

        let mut ct_res = executor.execute(&mut ctxt);
        let mut clear_res = signed_neg_under_modulus(clear, modulus);
        let dec: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(clear_res, dec);

        for _ in 0..NB_TESTS_SMALLER {
            ct_res = executor.execute(&mut ct_res);
            clear_res = signed_neg_under_modulus(clear_res, modulus);

            let dec: i64 = cks.decrypt_signed(&ct_res);
            println!("clear_res: {clear_res}, dec : {dec}");
            assert_eq!(clear_res, dec);
        }
    }
}

pub(crate) fn signed_default_neg_test<P, T>(param: P, mut executor: T)
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

    // -modulus is a special case, its negation cannot be
    // represented. rust by default returns -modulus
    // (which is what two complement result in)
    {
        let clear = -modulus;
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: i64 = cks.decrypt_signed(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<i64>() % modulus;

        let ctxt = cks.encrypt_signed(clear);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: i64 = cks.decrypt_signed(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
    }
}
