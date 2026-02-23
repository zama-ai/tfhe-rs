use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, signed_add_under_modulus, signed_overflowing_add_under_modulus,
    MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor,
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

create_parameterized_test!(integer_signed_unchecked_scalar_add);
create_parameterized_test!(integer_signed_default_scalar_add);
create_parameterized_test!(integer_signed_default_overflowing_scalar_add);

fn integer_signed_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_add);
    signed_unchecked_scalar_add_test(param, executor);
}

fn integer_signed_default_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    signed_default_scalar_add_test(param, executor);
}

fn integer_signed_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_add_parallelized);
    signed_default_overflowing_scalar_add_test(param, executor);
}
pub(crate) fn signed_unchecked_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, -1, modulus - 1),
        (modulus - 1, 1, -modulus),
        (-modulus, -2, modulus - 2),
        (modulus - 2, 2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    let mut clear;

    let mut rng = rand::rng();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<i64>() % modulus;
            let clear_1 = rng.gen::<i64>() % modulus;

            let ctxt_0 = cks.encrypt_signed_radix(clear_0, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());

            clear = signed_add_under_modulus(clear_0, clear_1, modulus);

            // add multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                let tmp = executor.execute((&ct_res, clear_1));
                ct_res = executor.execute((&ct_res, clear_1));
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(ct_res, tmp);
                clear = signed_add_under_modulus(clear, clear_1, modulus);

                let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}

pub(crate) fn signed_default_overflowing_scalar_add_test<P, T>(param: P, mut executor: T)
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
            #[cfg(feature = "gpu")]
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::NOMINAL);

            #[cfg(not(feature = "gpu"))]
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
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
