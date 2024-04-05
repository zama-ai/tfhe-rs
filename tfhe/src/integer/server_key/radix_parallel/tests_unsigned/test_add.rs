use super::{
    overflowing_add_under_modulus, panic_if_any_block_info_exceeds_max_degree_or_noise,
    panic_if_any_block_is_not_clean, panic_if_any_block_values_exceeds_its_degree,
    random_non_zero_value, unsigned_modulus, CpuFunctionExecutor, ExpectedDegrees,
    ExpectedNoiseLevels, NB_CTXT, NB_TESTS, NB_TESTS_SMALLER,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_sum_ciphertexts_vec_test, FunctionExecutor,
};
use crate::integer::tests::create_parametrized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_smart_add);
create_parametrized_test!(integer_default_add);
create_parametrized_test!(integer_default_overflowing_add);
create_parametrized_test!(integer_unchecked_add);
create_parametrized_test!(integer_unchecked_add_assign);
create_parametrized_test!(
    integer_default_add_work_efficient {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(integer_default_sum_ciphertexts_vec);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_parallelized);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_assign_parallelized);
    unchecked_add_assign_test(param, executor);
}

fn integer_smart_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_add_parallelized);
    smart_add_test(param, executor);
}

fn integer_default_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    default_add_test(param, executor);
}

fn integer_default_add_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized_work_efficient);
    default_add_test(param, executor);
}

fn integer_default_overflowing_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    default_overflowing_add_test(param, executor);
}

impl ExpectedNoiseLevels {
    fn after_unchecked_add(&mut self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> &Self {
        self.set_with(
            lhs.blocks
                .iter()
                .zip(rhs.blocks.iter())
                .map(|(a, b)| a.noise_level + b.noise_level),
        );
        self
    }
}

impl ExpectedDegrees {
    fn after_unchecked_add(&mut self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> &Self {
        self.set_with(
            lhs.blocks
                .iter()
                .zip(rhs.blocks.iter())
                .map(|(a, b)| a.degree + b.degree),
        );
        self
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn unchecked_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::ZERO, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let encrypted_result = executor.execute((&ctxt_0, &ctxt_1));

        expected_noise_levels
            .after_unchecked_add(&ctxt_0, &ctxt_1)
            .panic_if_any_is_not_equal(&encrypted_result);
        expected_degrees
            .after_unchecked_add(&ctxt_0, &ctxt_1)
            .panic_if_any_is_not_equal(&encrypted_result);
        panic_if_any_block_values_exceeds_its_degree(&encrypted_result, &cks);
        panic_if_any_block_info_exceeds_max_degree_or_noise(
            &encrypted_result,
            max_degree,
            max_noise_level,
        );

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected_result = clear_0.wrapping_add(clear_1) % modulus;

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid add result, expected {clear_0} + {clear_1} \
            to be {expected_result}, but got {decrypted_result}."
        );
    }
}

pub(crate) fn unchecked_add_assign_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::ZERO, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        // Compute expected values before the add_assign changes them
        expected_noise_levels.after_unchecked_add(&ctxt_0, &ctxt_1);
        expected_degrees.after_unchecked_add(&ctxt_0, &ctxt_1);

        executor.execute((&mut ctxt_0, &ctxt_1));

        expected_noise_levels.panic_if_any_is_not_equal(&ctxt_0);
        expected_degrees.panic_if_any_is_not_equal(&ctxt_0);
        panic_if_any_block_values_exceeds_its_degree(&ctxt_0, &cks);
        panic_if_any_block_info_exceeds_max_degree_or_noise(&ctxt_0, max_degree, max_noise_level);

        let decrypted_result: u64 = cks.decrypt(&ctxt_0);
        let expected_result = clear_0.wrapping_add(clear_1) % modulus;

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid add result, expected {clear_0} + {clear_1} \
            to be {expected_result}, but got {decrypted_result}."
        );
    }
}

//=============================================================================
// Smart Tests
//=============================================================================

pub(crate) fn smart_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));

        clear = clear_0.wrapping_add(clear_1) % modulus;
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear, dec_res);

        // Add multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = executor.execute((&mut ct_res, &mut ctxt_0));

            panic_if_any_block_info_exceeds_max_degree_or_noise(
                &ct_res,
                max_degree,
                max_noise_level,
            );
            panic_if_any_block_values_exceeds_its_degree(&ct_res, &cks);

            clear = clear.wrapping_add(clear_0) % modulus;
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

//=============================================================================
// Default Tests
//=============================================================================

pub(crate) fn default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let tmp_ct = executor.execute((&ctxt_0, &ctxt_1));

        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(ct_res, tmp_ct);

        clear = clear_0.wrapping_add(clear_1) % modulus;
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear, dec_res);

        for _ in 0..NB_TESTS_SMALLER {
            ct_res = executor.execute((&ct_res, &ctxt_0));
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            clear = (clear + clear_0) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
        let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, &ctxt_1));
        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

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

        for _ in 0..NB_TESTS_SMALLER {
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

fn integer_default_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &ServerKey, ctxt: &Vec<RadixCiphertext>| -> Option<RadixCiphertext> {
        sks.sum_ciphertexts_parallelized(ctxt)
    };
    let executor = CpuFunctionExecutor::new(sum_vec);
    default_sum_ciphertexts_vec_test(param, executor);
}
