use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, random_non_zero_value, signed_add_under_modulus,
    signed_overflowing_add_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, nb_unchecked_tests_for_params,
    CpuFunctionExecutor, MAX_NB_CTXT,
};
use crate::integer::server_key::radix_parallel::OutputFlag;
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

create_parameterized_test!(integer_signed_unchecked_add);
create_parameterized_test!(integer_signed_unchecked_overflowing_add);
create_parameterized_test!(
    integer_signed_unchecked_overflowing_add_parallelized {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(integer_signed_smart_add);
create_parameterized_test!(integer_signed_default_add);
create_parameterized_test!(integer_extensive_trivial_signed_default_add);
create_parameterized_test!(integer_signed_default_overflowing_add);
create_parameterized_test!(integer_extensive_trivial_signed_overflowing_add);
create_parameterized_test!(
    integer_extensive_trivial_signed_advanced_overflowing_add_assign_with_carry_sequential
);
create_parameterized_test!(
    integer_extensive_trivial_signed_overflowing_advanced_add_assign_with_carry_at_least_4_bits {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);

fn integer_signed_unchecked_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_parallelized);
    signed_unchecked_add_test(param, executor);
}

fn integer_signed_unchecked_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_signed_overflowing_add);
    signed_unchecked_overflowing_add_test(param, executor);
}

fn integer_signed_unchecked_overflowing_add_parallelized<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_signed_overflowing_add_parallelized);
    signed_unchecked_overflowing_add_test(param, executor);
}

fn integer_signed_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_add_parallelized);
    signed_default_overflowing_add_test(param, executor);
}

fn integer_extensive_trivial_signed_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_add_parallelized);
    extensive_trivial_signed_default_overflowing_add_test(param, executor);
}

fn integer_signed_default_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    signed_default_add_test(param, executor);
}

fn integer_extensive_trivial_signed_default_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    extensive_trivial_signed_default_add_test(param, executor);
}

fn integer_extensive_trivial_signed_advanced_overflowing_add_assign_with_carry_sequential<P>(
    param: P,
) where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, lhs: &SignedRadixCiphertext, rhs: &SignedRadixCiphertext| {
        let mut result = lhs.clone();
        let overflowed = sks
            .advanced_add_assign_with_carry_sequential_parallelized(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Overflow,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    extensive_trivial_signed_default_overflowing_add_test(param, executor);
}

fn integer_extensive_trivial_signed_overflowing_advanced_add_assign_with_carry_at_least_4_bits<P>(
    param: P,
) where
    P: Into<TestParameters>,
{
    // We explicitly call the 4 bit function to make sure it's being tested,
    // no matter the number of blocks / threads available
    let func = |sks: &ServerKey, lhs: &SignedRadixCiphertext, rhs: &SignedRadixCiphertext| {
        let mut result = lhs.clone();
        let overflowed = sks
            .advanced_add_assign_with_carry_at_least_4_bits(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Overflow,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    extensive_trivial_signed_default_overflowing_add_test(param, executor);
}

fn integer_signed_smart_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_add_parallelized);
    signed_smart_add_test(param, executor);
}

pub(crate) fn signed_unchecked_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    >,
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
    let hardcoded_values = [
        (-modulus, -1),
        (modulus - 1, 1),
        (-1, -modulus),
        (1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
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

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
        let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check,\n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nct0: {ctxt_0:?}, \n\n\nct1: {ctxt_1:?}\n\n\n");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nct0: {ctxt_0:?}, \n\n\nct1: {ctxt_1:?}\n\n\n");

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
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
    }

    // Test with trivial inputs, as it was bugged at some point
    let values = [
        (rng.gen::<i64>() % modulus, 0i64),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
    ];
    for (clear_0, clear_1) in values {
        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = executor.execute((&a, &b));

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
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
    }
}

pub(crate) fn signed_default_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
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

    for num_blocks in 1..MAX_NB_CTXT {
        let half_modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if half_modulus <= 1 {
            // The half_modulus (i.e modulus without sign bit) is such that the set of values
            // is empty
            continue;
        }

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<i64>() % half_modulus;
            let clear_1 = rng.gen::<i64>() % half_modulus;

            let ctxt_0 = cks.as_ref().encrypt_signed_radix(clear_0, num_blocks);
            let ctxt_1 = cks.as_ref().encrypt_signed_radix(clear_1, num_blocks);

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
            let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, &ctxt_1));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nct0: {ctxt_0:?}, \n\n\nct1: {ctxt_1:?}\n\n\n");
            assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nct0: {ctxt_0:?}, \n\n\nct1: {ctxt_1:?}\n\n\n");

            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, half_modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {half_modulus} \
             expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {half_modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

            for _ in 0..nb_tests_smaller {
                // Add non zero scalar to have non clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, half_modulus);
                let clear_3 = random_non_zero_value(&mut rng, half_modulus);

                let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
                let ctxt_1 = sks.unchecked_scalar_add(&ctxt_1, clear_3);

                let clear_lhs = signed_add_under_modulus(clear_0, clear_2, half_modulus);
                let clear_rhs = signed_add_under_modulus(clear_1, clear_3, half_modulus);

                let d0: i64 = cks.decrypt_signed(&ctxt_0);
                assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
                let d1: i64 = cks.decrypt_signed(&ctxt_1);
                assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

                let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
                assert!(ct_res.block_carries_are_empty());

                let (expected_result, expected_overflowed) =
                    signed_overflowing_add_under_modulus(clear_lhs, clear_rhs, half_modulus);

                let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
                let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for add, for ({clear_lhs} + {clear_rhs}) % {half_modulus} \
                expected {expected_result}, got {decrypted_result}"
                );
                assert_eq!(
                    decrypted_overflowed,
                    expected_overflowed,
                    "Invalid overflow flag result for overflowing_add, for ({clear_lhs} + {clear_rhs}) % {half_modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
                );
                assert_eq!(result_overflowed.0.degree.get(), 1);
                assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
            }
        }
    }
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    // Test with trivial inputs, as it was bugged at some point
    for _ in 0..4 {
        // Reduce maximum value of random number such that at least the last block is a trivial 0
        // (This is how the reproducing case was found)
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_add_parallelized(&a, &b);

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
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

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_signed_default_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let message_modulus = cks.parameters().message_modulus();
    let block_num_bits = message_modulus.0.ilog2();
    for bit_size in 2..=64u32 {
        let num_blocks = bit_size.div_ceil(block_num_bits);
        let modulus = (cks.parameters().message_modulus().0 as i128).pow(num_blocks) / 2;

        for _ in 0..50 {
            let clear_0 = rng.gen::<i128>() % modulus;
            let clear_1 = rng.gen::<i128>() % modulus;

            let ctxt_0 = sks.create_trivial_radix(clear_0, num_blocks as usize);
            let ctxt_1 = sks.create_trivial_radix(clear_1, num_blocks as usize);

            let (ct_res, ct_overflow) = executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: i128 = cks.decrypt_signed(&ct_res);
            let dec_overflow = cks.decrypt_bool(&ct_overflow);

            let (expected_clear, expected_overflow) =
                signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);
            assert_eq!(
                expected_clear, dec_res,
                "Invalid result for {clear_0} + {clear_1}, expected: {expected_clear}, got: {dec_res}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
            assert_eq!(
                expected_overflow, dec_overflow,
                "Invalid overflow result for {clear_0} + {clear_1}, expected: {expected_overflow}, got: {dec_overflow}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
        }
    }
}

pub(crate) fn signed_unchecked_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_unchecked_tests = nb_unchecked_tests_for_params(param);
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
        let ctxt_1 = cks.encrypt_signed(clear_1);
        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs(&mut rng, modulus, nb_unchecked_tests)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let mut clear;

    for num_blocks in 1..MAX_NB_CTXT {
        let half_modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if half_modulus <= 1 {
            // The half_modulus (i.e modulus without sign bit) is such that the set of values
            // is empty
            continue;
        }

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<i64>() % half_modulus;
            let clear_1 = rng.gen::<i64>() % half_modulus;

            let ctxt_0 = cks.as_ref().encrypt_signed_radix(clear_0, num_blocks);
            let ctxt_1 = cks.as_ref().encrypt_signed_radix(clear_1, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
            let tmp_ct = executor.execute((&ctxt_0, &ctxt_1));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct);

            clear = signed_add_under_modulus(clear_0, clear_1, half_modulus);

            // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
            // add multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                ct_res = executor.execute((&ct_res, &ctxt_0));
                assert!(ct_res.block_carries_are_empty());
                clear = signed_add_under_modulus(clear, clear_0, half_modulus);

                let dec_res: i64 = cks.decrypt_signed(&ct_res);

                // println!("clear = {}, dec_res = {}", clear, dec_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_signed_default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let message_modulus = cks.parameters().message_modulus();
    let block_num_bits = message_modulus.0.ilog2();
    for bit_size in 2..=64u32 {
        let num_blocks = bit_size.div_ceil(block_num_bits);
        let modulus = (cks.parameters().message_modulus().0 as i128).pow(num_blocks) / 2;

        for _ in 0..50 {
            let clear_0 = rng.gen::<i128>() % modulus;
            let clear_1 = rng.gen::<i128>() % modulus;

            let ctxt_0 = sks.create_trivial_radix(clear_0, num_blocks as usize);
            let ctxt_1 = sks.create_trivial_radix(clear_1, num_blocks as usize);

            let ct_res = executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: i128 = cks.decrypt_signed(&ct_res);

            let expected_clear = signed_add_under_modulus(clear_0, clear_1, modulus);
            assert_eq!(
                expected_clear, dec_res,
                "Invalid result for {clear_0} + {clear_1}, expected: {expected_clear}, got: {dec_res}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
        }
    }
}

pub(crate) fn signed_smart_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut SignedRadixCiphertext, &'a mut SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen_range(-modulus..modulus);
        let clear_1 = rng.gen_range(-modulus..modulus);

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let mut ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));
        clear = signed_add_under_modulus(clear_0, clear_1, modulus);
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(clear, dec_res);

        // add multiple times to raise the degree
        for _ in 0..nb_tests_smaller {
            ct_res = executor.execute((&mut ct_res, &mut ctxt_0));
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}
