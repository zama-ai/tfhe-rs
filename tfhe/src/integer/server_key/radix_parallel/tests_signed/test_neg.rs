use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, signed_neg_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, nb_unchecked_tests_for_params, CpuFunctionExecutor, MAX_NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_neg);
create_parameterized_test!(integer_signed_smart_neg);
create_parameterized_test!(integer_signed_default_neg);
create_parameterized_test!(integer_signed_default_overflowing_neg);

fn integer_signed_unchecked_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_neg);
    signed_unchecked_neg_test(param, executor);
}

fn integer_signed_smart_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    signed_smart_neg_test(param, executor);
}

fn integer_signed_default_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    signed_default_neg_test(param, executor);
}

fn integer_signed_default_overflowing_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::overflowing_neg_parallelized);
    default_overflowing_neg_test(param, executor);
}

pub(crate) fn signed_unchecked_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_unchecked_tests = nb_unchecked_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let ctxt_zero = sks.create_trivial_radix(0i64, NB_CTXT);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

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
        create_iterator_of_signed_random_pairs(&mut rng, modulus, nb_unchecked_tests)
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a mut SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear = rng.gen::<i64>() % modulus;

        let mut ctxt = cks.encrypt_signed(clear);

        let mut ct_res = executor.execute(&mut ctxt);
        let mut clear_res = signed_neg_under_modulus(clear, modulus);
        let dec: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(clear_res, dec);

        for _ in 0..nb_tests_smaller {
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

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

    for _ in 0..nb_tests_smaller {
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

pub(crate) fn default_overflowing_neg_test<P, T>(param: P, mut overflowing_neg: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, (SignedRadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((
        cks,
        crate::integer::server_key::radix_parallel::tests_cases_unsigned::NB_CTXT,
    ));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    overflowing_neg.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;

        if modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests_smaller {
            let clear = rng.gen_range(-modulus + 1..modulus);
            let ctxt = cks.encrypt_signed_radix(clear, num_blocks);

            let (ct_res, flag) = overflowing_neg.execute(&ctxt);

            assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(flag.0.degree.get(), 1);

            let dec_flag = cks.decrypt_bool(&flag);
            assert!(
                !dec_flag,
                "Invalid flag result for overflowing_neg({clear}),\n\
                Expected false, got true\n\
                num_blocks: {num_blocks}, modulus: {:?}",
                -modulus..modulus
            );

            let dec_ct: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct,
                expected,
                "Invalid result for overflowing_neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {:?}",
                -modulus..modulus
            );

            let (ct_res2, flag2) = overflowing_neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
            assert_eq!(flag, flag2, "Failed determinism check");
        }

        // The only case where signed neg does overflows
        let ctxt = cks.encrypt_signed_radix(-modulus, num_blocks);

        let (ct_res, flag) = overflowing_neg.execute(&ctxt);

        assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
        assert_eq!(flag.0.degree.get(), 1);

        let dec_flag = cks.decrypt_bool(&flag);
        assert!(
            dec_flag,
            "Invalid flag result for overflowing_neg({}),\n\
            Expected true, got false\n\
            num_blocks: {num_blocks}, modulus: {:?}",
            -modulus,
            -modulus..modulus
        );

        let dec_ct: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(
            dec_ct,
            -modulus,
            "Invalid result for overflowing_neg({}),\n\
            Expected {}, got {dec_ct}\n\
            num_blocks: {num_blocks}, modulus: {:?}",
            -modulus,
            -modulus,
            -modulus..modulus
        );
    }
}
