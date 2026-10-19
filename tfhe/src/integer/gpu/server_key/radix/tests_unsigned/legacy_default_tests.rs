//! Pre-harness versions of the default operation tests still used by the GPU backend.
//!
//! FIXME(gpu): the CPU tests for these operations moved to
//! `radix_parallel::test_harness` (see `radix_parallel::tests_unsigned::test_add`,
//! `test_scalar_add`, `test_scalar_shift`, `test_scalar_rotate`, `test_sum` and `test_neg`),
//! which also
//! exercises inputs at the maximum degree and noise level.
//! The GPU full propagation cannot take blocks at the maximum degree yet.
//! Once it is aligned with the CPU one point the GPU wrappers at the harness
//! tests and delete this file.
use crate::integer::ciphertext::{IntegerCiphertext, IntegerRadixCiphertext};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, overflowing_add_under_modulus,
    panic_if_any_block_is_not_clean, random_non_zero_value, rotate_left_helper,
    rotate_right_helper, unsigned_modulus, MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

pub(crate) fn legacy_default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let mut clear;

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.as_ref().encrypt_radix(clear_0, num_blocks);
        let ctxt_1 = cks.as_ref().encrypt_radix(clear_1, num_blocks);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let tmp_ct = executor.execute((&ctxt_0, &ctxt_1));

        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(ct_res, tmp_ct);

        clear = clear_0.wrapping_add(clear_1) % modulus;
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(
            clear, dec_res,
            "Invalid result for {clear_0} + {clear_1}, expected: {clear}, got: {dec_res}\n\
             num_blocks={num_blocks}, modulus={modulus}"
        );

        for _ in 0..nb_tests_smaller {
            ct_res = executor.execute((&ct_res, &ctxt_0));
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let result = (clear + clear_0) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(
                result, dec_res,
                "Invalid result for {clear} + {clear_0}, expected: {result}, got: {dec_res}\n\
             num_blocks={num_blocks}, modulus={modulus}"
            );
            clear = result;
        }
    }
}

pub(crate) fn legacy_default_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
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

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.as_ref().encrypt_radix(clear_0, num_blocks);
        let ctxt_1 = cks.as_ref().encrypt_radix(clear_1, num_blocks);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
        let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, &ctxt_1));
        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nctxt1: {ctxt_1:?}\n\n\n");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nctxt1: {ctxt_1:?}\n\n\n");

        let (expected_result, expected_overflowed) =
            overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: u64 = cks.decrypt(&ct_res);
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
            // Add non-zero scalar to have non-clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_3 = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let ctxt_1 = sks.unchecked_scalar_add(&ctxt_1, clear_3);

            let (clear_lhs, _) = overflowing_add_under_modulus(clear_0, clear_2, modulus);
            let (clear_rhs, _) = overflowing_add_under_modulus(clear_1, clear_3, modulus);

            let d0: u64 = cks.decrypt(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
            let d1: u64 = cks.decrypt(&ctxt_1);
            assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let (expected_result, expected_overflowed) =
                overflowing_add_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: u64 = cks.decrypt(&ct_res);
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
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);
    for _ in 0..4 {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let a: RadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: RadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = executor.execute((&a, &b));

        let (expected_result, expected_overflowed) =
            overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
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
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

pub(crate) fn legacy_default_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    let mut clear;

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_0 = cks.encrypt_radix(clear_0, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());

            clear = (clear_0 + clear_1) % modulus;

            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(
                clear, dec_res,
                "invalid result for ({clear_0} + {clear_1}) % {modulus} (num_blocks: {num_blocks})"
            );

            // Add multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                let tmp = executor.execute((&ct_res, clear_1));
                ct_res = executor.execute((&ct_res, clear_1));
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(ct_res, tmp);
                clear = clear.wrapping_add(clear_1) % modulus;

                let dec_res: u64 = cks.decrypt_radix(&ct_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}

pub(crate) fn legacy_default_scalar_left_shift_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.checked_shl(scalar).unwrap_or(0) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            // An overshift pushes every bit out, so a left shift returns 0.
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(0, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;
    let ct = cks.encrypt(clear);

    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = executor.execute((&ct, scalar as u64));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
    }
}

pub(crate) fn legacy_default_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    for _ in 0..nb_tests_smaller {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            // An overshift pushes every bit out, so an unsigned right shift returns 0.
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(0, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;

    let ct = cks.encrypt(clear);
    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = executor.execute((&ct, scalar as u64));
        let tmp = executor.execute((&ct, scalar as u64));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
    }
}

pub(crate) fn legacy_default_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::thread_rng();

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

pub(crate) fn legacy_default_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::thread_rng();

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

pub(crate) fn legacy_default_sum_ciphertexts_vec_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..nb_tests_smaller {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            let mut ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            // One of the inputs has non empty carries, to exercise the path where the
            // implementation has to propagate an input before summing. The other inputs
            // are left clean, so both paths are covered.
            let extra_clear = rng.gen::<u64>() % modulus;
            let extra_ctxt = cks.encrypt(extra_clear);
            let dirty_index = rng.gen_range(0..ctxts.len());
            sks.unchecked_add_assign(&mut ctxts[dirty_index], &extra_ctxt);
            assert!(!ctxts[dirty_index].block_carries_are_empty());

            // Another input has empty carries but a noise level above nominal, so the noise
            // half of the cleanliness check is exercised too. No cheap operation raises the
            // noise without also filling the carries, so the metadata is set directly. The
            // real noise being lower than advertised does not matter for what is tested here.
            if ctxts.len() >= 2 {
                let noisy_index = (dirty_index + 1) % ctxts.len();
                for block in ctxts[noisy_index].blocks_mut() {
                    block.set_noise_level(
                        NoiseLevel::NOMINAL + NoiseLevel::NOMINAL,
                        sks.key.max_noise_level,
                    );
                }
                assert!(ctxts[noisy_index].block_carries_are_empty());
                assert!(!ctxts[noisy_index].is_clean());
            }

            let ct_res = executor.execute(&ctxts).unwrap();
            let res: u64 = cks.decrypt(&ct_res);
            let clear = (clears.iter().sum::<u64>() + extra_clear) % modulus;

            assert_eq!(res, clear);

            let ct_res_2 = executor.execute(&ctxts).unwrap();
            assert_eq!(ct_res, ct_res_2, "Failed determinism check");
        }
    }
}

pub(crate) fn legacy_default_neg_test<P, T>(param: P, mut neg: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks.clone());

    let mut rng = rand::thread_rng();

    neg.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let mut clear = rng.gen_range(0..modulus);
            let mut ctxt = cks.encrypt_radix(clear, num_blocks);

            let ct_res = neg.execute(&ctxt);
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );

            let ct_res2 = neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");

            // Test with non clean carries
            let random_non_zero = random_non_zero_value(&mut rng, modulus);
            sks.unchecked_scalar_add_assign(&mut ctxt, random_non_zero);
            clear = clear.wrapping_add(random_non_zero) % modulus;

            let ct_res = neg.execute(&ctxt);
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );
            let ct_res2 = neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

pub(crate) fn legacy_default_overflowing_neg_test<P, T>(param: P, mut overflowing_neg: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    overflowing_neg.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear = rng.gen_range(1..modulus);
            let ctxt = cks.encrypt_radix(clear, num_blocks);

            let (ct_res, flag) = overflowing_neg.execute(&ctxt);

            panic_if_any_block_is_not_clean(&ct_res, &cks);
            assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(flag.0.degree.get(), 1);

            let dec_flag = cks.decrypt_bool(&flag);
            assert!(
                dec_flag,
                "Invalid value for overflowing_neg flag, expected true, got false"
            );

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for overflowing_neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );

            let (ct_res2, flag2) = overflowing_neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
            assert_eq!(flag, flag2, "Failed determinism check");
        }

        // The only case where unsigned neg does not overflows
        let ctxt = cks.encrypt_radix(0u32, num_blocks);

        let (ct_res, flag) = overflowing_neg.execute(&ctxt);

        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
        assert_eq!(flag.0.degree.get(), 1);

        let dec_flag = cks.decrypt_bool(&flag);
        assert!(
            !dec_flag,
            "Invalid value for overflowing_neg flag, expected false, got true"
        );

        let dec_ct: u64 = cks.decrypt_radix(&ct_res);
        assert_eq!(
            dec_ct, 0,
            "Invalid result for overflowing_neg(0),\n\
                Expected 0, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
        );
    }
}
