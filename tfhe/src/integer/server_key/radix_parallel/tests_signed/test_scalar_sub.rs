use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, signed_add_under_modulus, signed_overflowing_add_under_modulus,
    signed_overflowing_sub_under_modulus, signed_sub_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor, MAX_NB_CTXT,
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

create_parameterized_test!(integer_signed_unchecked_scalar_sub);
create_parameterized_test!(integer_signed_default_overflowing_scalar_sub);
create_parameterized_test!(integer_signed_unchecked_left_scalar_sub);
create_parameterized_test!(integer_signed_smart_left_scalar_sub);
create_parameterized_test!(integer_signed_default_left_scalar_sub);

fn integer_signed_unchecked_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_sub);
    signed_unchecked_scalar_sub_test(param, executor);
}

fn integer_signed_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_sub_parallelized);
    signed_default_overflowing_scalar_sub_test(param, executor);
}

fn integer_signed_unchecked_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_scalar_sub);
    signed_unchecked_left_scalar_sub_test(param, executor);
}

fn integer_signed_smart_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_left_scalar_sub_parallelized);
    signed_smart_left_scalar_sub_test(param, executor);
}

fn integer_signed_default_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::left_scalar_sub_parallelized);
    signed_default_left_scalar_sub_test(param, executor);
}

pub(crate) fn signed_unchecked_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, 1, modulus - 1),
        (modulus - 1, -1, -modulus),
        (-modulus, 2, modulus - 2),
        (modulus - 2, -2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_overflowing_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    let hardcoded_values = [
        (-modulus, 1),
        (modulus - 1, -1),
        (1, -modulus),
        (-1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
    }

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
        let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, \n\n\nct: {ctxt_0:?}, \n\n\nclear: {clear_1:?}\n\n\n");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, \n\n\nct: {ctxt_0:?}, \n\n\nclear: {clear_1:?}\n\n\n");

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..nb_tests_smaller {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_rhs = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let (clear_lhs, _) = signed_overflowing_add_under_modulus(clear_0, clear_2, modulus);
            let d0: i64 = cks.decrypt_signed(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_rhs));
            assert!(ct_res.block_carries_are_empty());
            let (expected_result, expected_overflowed) =
                signed_overflowing_sub_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for sub, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub, for ({clear_lhs} - {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    // Test with trivial inputs
    for _ in 0..4 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        #[cfg(feature = "gpu")]
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::NOMINAL);

        #[cfg(not(feature = "gpu"))]
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }

    // Test with scalar that is bigger than ciphertext modulus
    for _ in 0..2 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen_range(modulus..=i64::MAX);

        let a = cks.encrypt_signed(clear_0);

        let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert!(decrypted_overflowed); // Actually we know its an overflow case
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

pub(crate) fn signed_unchecked_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(i64, &'a SignedRadixCiphertext), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let clear_lhs = rng.gen::<i64>() % modulus;
            let mut clear_rhs = rng.gen::<i64>() % modulus;

            let mut ct_rhs = cks.encrypt_signed_radix(clear_rhs, num_blocks);

            ct_rhs = executor.execute((clear_lhs, &ct_rhs));
            clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);

            let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
            assert_eq!(dec_res, clear_rhs);

            let mut clear_lhs = rng.gen::<i64>() % modulus;
            while sks.is_left_scalar_sub_possible(clear_lhs, &ct_rhs).is_ok() {
                ct_rhs = executor.execute((clear_lhs, &ct_rhs));
                clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);
                let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
                assert_eq!(dec_res, clear_rhs);
                clear_lhs = rng.gen::<i64>() % modulus;
            }
        }
    }
}

pub(crate) fn signed_smart_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(i64, &'a mut SignedRadixCiphertext), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if modulus <= 1 {
            continue;
        }

        let clear_lhs = rng.gen::<i64>() % modulus;
        let mut clear_rhs = rng.gen::<i64>() % modulus;

        let mut ct_rhs = cks.encrypt_signed_radix(clear_rhs, num_blocks);

        ct_rhs = executor.execute((clear_lhs, &mut ct_rhs));
        clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
        assert_eq!(dec_res, clear_rhs);
        for _ in 0..nb_tests {
            let clear_lhs = rng.gen::<i64>() % modulus;

            ct_rhs = executor.execute((clear_lhs, &mut ct_rhs));
            clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
            assert_eq!(dec_res, clear_rhs);
        }
    }
}

pub(crate) fn signed_default_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(i64, &'a SignedRadixCiphertext), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let clear_0 = rng.gen::<i64>() % modulus;
            let clear_1 = rng.gen::<i64>() % modulus;

            let ctxt_1 = cks.encrypt_signed_radix(clear_1, num_blocks);

            let ct_res = executor.execute((clear_0, &ctxt_1));
            assert!(ct_res.block_carries_are_empty());

            let tmp = executor.execute((clear_0, &ctxt_1));
            assert_eq!(ct_res, tmp, "Operation is not deterministic");

            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            assert_eq!(dec_res, signed_sub_under_modulus(clear_0, clear_1, modulus));

            let non_zero = random_non_zero_value(&mut rng, modulus);
            let non_clean = sks.unchecked_scalar_add(&ctxt_1, non_zero);
            let ct_res = executor.execute((clear_0, &non_clean));
            assert!(ct_res.block_carries_are_empty());
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = signed_sub_under_modulus(
                clear_0,
                signed_add_under_modulus(clear_1, non_zero, modulus),
                modulus,
            );
            assert_eq!(dec_res, expected);

            let ct_res2 = executor.execute((clear_0, &non_clean));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}
