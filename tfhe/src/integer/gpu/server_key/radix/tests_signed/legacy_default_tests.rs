//! Pre-harness versions of the signed default operation tests still used by the GPU backend.
//!
//! FIXME(gpu): the CPU tests for these operations moved to `radix_parallel::test_harness`
//! (see `radix_parallel::tests_signed::test_scalar_shift`, `test_scalar_rotate`,
//! `test_scalar_add` and `test_scalar_sub`), which also exercises inputs at the maximum
//! degree and noise level. The GPU full propagation cannot take blocks at the maximum degree
//! yet. The overflowing scalar tests also cover scalars that fit the radix blocks but not
//! the signed range, for which the GPU implementations return the opposite overflow flag:
//! the CPU fix is `ScalarOverflowFlagSource` in `radix_parallel::scalar_add`, which the GPU
//! can reuse. Once both are addressed point the GPU wrappers at the harness tests and delete
//! this file.
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, rotate_left_helper, rotate_right_helper, signed_add_under_modulus,
    signed_left_shift_under_modulus, signed_overflowing_add_under_modulus,
    signed_overflowing_sub_under_modulus, signed_right_shift_under_modulus,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, SignedRadixCiphertext};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

pub(crate) fn legacy_signed_default_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            // An overshift pushes every bit out, so a left shift returns 0.
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = 0i64;
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

pub(crate) fn legacy_signed_default_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            // An overshift saturates an arithmetic right shift to the sign: -1 if negative, else 0.
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = if clear < 0 { -1i64 } else { 0i64 };
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

pub(crate) fn legacy_signed_default_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

pub(crate) fn legacy_signed_default_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

pub(crate) fn legacy_signed_default_overflowing_scalar_sub_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::thread_rng();

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
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::NOMINAL);
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

pub(crate) fn legacy_signed_default_overflowing_scalar_add_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    // If a block encrypts 1 bit (message_modulus == 2), then it
    // makes no sense to only have one block, as the block would only encrypt the sign bit
    let start = if cks.parameters().message_modulus().0 > 2 {
        1
    } else {
        2
    };
    for num_blocks in start..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;

        let hardcoded_values = [
            (-modulus, -1),
            (modulus - 1, 1),
            (-1, -modulus),
            (1, modulus - 1),
        ];
        for (clear_0, clear_1) in hardcoded_values {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, num_blocks);

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: i64 = cks.decrypt_signed_radix(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<i64>() % modulus;
            let clear_1 = rng.gen::<i64>() % modulus;

            let ctxt_0 = cks.encrypt_signed_radix(clear_0, num_blocks);

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
            let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct, "Failed determinism check,\n\n\n msg0: {clear_0}, msg1: {clear_1},  \n\n\nct: {ctxt_0:?}, \n\n\nclear: {clear_1:?}\n\n\n");
            assert_eq!(tmp_o, result_overflowed, "Failed determinism check,\n\n\n msg0: {clear_0}, msg1: {clear_1},  \n\n\nct: {ctxt_0:?}, \n\n\nclear: {clear_1:?}\n\n\n");

            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: i64 = cks.decrypt_signed_radix(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

            for _ in 0..nb_tests_smaller {
                // Add non zero scalar to have non clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear_rhs = random_non_zero_value(&mut rng, modulus);

                let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
                let (clear_lhs, _) =
                    signed_overflowing_add_under_modulus(clear_0, clear_2, modulus);
                let d0: i64 = cks.decrypt_signed_radix(&ctxt_0);
                assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

                let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_rhs));
                assert!(ct_res.block_carries_are_empty());
                let (expected_result, expected_overflowed) =
                    signed_overflowing_add_under_modulus(clear_lhs, clear_rhs, modulus);

                let decrypted_result: i64 = cks.decrypt_signed_radix(&ct_res);
                let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
                );
                assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
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

            let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: i64 = cks.decrypt_signed_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::NOMINAL);
        }

        // Test with scalar that is bigger than ciphertext modulus
        for _ in 0..2 {
            let clear_0 = rng.gen::<i64>() % modulus;
            let clear_1 = rng.gen_range(modulus..=i64::MAX);

            let a = cks.encrypt_signed_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: i64 = cks.decrypt_signed_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
            assert!(decrypted_overflowed); // Actually we know its an overflow case
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
        }
    }
}
