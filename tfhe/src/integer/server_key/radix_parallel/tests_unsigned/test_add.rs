use super::{
    nb_tests_for_params, nb_tests_smaller_for_params, overflowing_add_under_modulus,
    panic_if_any_block_info_exceeds_max_degree_or_noise, panic_if_any_block_is_not_clean,
    panic_if_any_block_values_exceeds_its_degree, random_non_zero_value, unsigned_modulus,
    unsigned_modulus_u128, CpuFunctionExecutor, ExpectedDegrees, ExpectedNoiseLevels, MAX_NB_CTXT,
    NB_CTXT,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_add);
create_parameterized_test!(integer_unchecked_add_assign);
create_parameterized_test!(integer_smart_add);
create_parameterized_test!(integer_default_add);
create_parameterized_test!(integer_extensive_trivial_default_add);
create_parameterized_test!(integer_default_overflowing_add);
create_parameterized_test!(integer_extensive_trivial_default_overflowing_add);
create_parameterized_test!(integer_advanced_overflowing_add_assign_with_carry_at_least_4_bits {
    coverage => {
        COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
    },
    no_coverage => {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64
    }
});
create_parameterized_test!(integer_advanced_add_assign_with_carry_sequential);
create_parameterized_test!(integer_extensive_trivial_overflowing_advanced_add_assign_with_carry_at_least_4_bits {
    coverage => {
        COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
    },
    no_coverage => {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64
    }
});
create_parameterized_test!(
    integer_extensive_trivial_advanced_overflowing_add_assign_with_carry_sequential
);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_parallelized);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_assign_parallelized);
    unchecked_add_assign_test(param, executor);
}

fn integer_smart_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_add_parallelized);
    smart_add_test(param, executor);
}

fn integer_default_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    default_add_test(param, executor);
}

fn integer_extensive_trivial_default_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    extensive_trivial_default_add_test(param, executor);
}

fn integer_advanced_overflowing_add_assign_with_carry_at_least_4_bits<P>(param: P)
where
    P: Into<TestParameters>,
{
    // We explicitly call the 4 bit function to make sure it's being tested,
    // no matter the number of blocks / threads available
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        if !result.block_carries_are_empty() {
            sks.full_propagate_parallelized(&mut result);
        }
        let mut tmp_rhs;
        let rhs = if rhs.block_carries_are_empty() {
            rhs
        } else {
            tmp_rhs = rhs.clone();
            sks.full_propagate_parallelized(&mut tmp_rhs);
            &tmp_rhs
        };
        let overflowed = sks
            .advanced_add_assign_with_carry_at_least_4_bits(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Carry,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    default_overflowing_add_test(param, executor);
}

fn integer_extensive_trivial_overflowing_advanced_add_assign_with_carry_at_least_4_bits<P>(param: P)
where
    P: Into<TestParameters>,
{
    // We explicitly call the 4 bit function to make sure it's being tested,
    // no matter the number of blocks / threads available
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        if !result.block_carries_are_empty() {
            sks.full_propagate_parallelized(&mut result);
        }
        let mut tmp_rhs;
        let rhs = if rhs.block_carries_are_empty() {
            rhs
        } else {
            tmp_rhs = rhs.clone();
            sks.full_propagate_parallelized(&mut tmp_rhs);
            &tmp_rhs
        };
        let overflowed = sks
            .advanced_add_assign_with_carry_at_least_4_bits(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Carry,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    extensive_trivial_default_overflowing_add_test(param, executor);
}

fn integer_advanced_add_assign_with_carry_sequential<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        if !result.block_carries_are_empty() {
            sks.full_propagate_parallelized(&mut result);
        }
        let mut tmp_rhs;
        let rhs = if rhs.block_carries_are_empty() {
            rhs
        } else {
            tmp_rhs = rhs.clone();
            sks.full_propagate_parallelized(&mut tmp_rhs);
            &tmp_rhs
        };
        let overflowed = sks
            .advanced_add_assign_with_carry_sequential_parallelized(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Carry,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    default_overflowing_add_test(param, executor);
}

fn integer_extensive_trivial_advanced_overflowing_add_assign_with_carry_sequential<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        if !result.block_carries_are_empty() {
            sks.full_propagate_parallelized(&mut result);
        }
        let mut tmp_rhs;
        let rhs = if rhs.block_carries_are_empty() {
            rhs
        } else {
            tmp_rhs = rhs.clone();
            sks.full_propagate_parallelized(&mut tmp_rhs);
            &tmp_rhs
        };
        let overflowed = sks
            .advanced_add_assign_with_carry_sequential_parallelized(
                &mut result.blocks,
                &rhs.blocks,
                None,
                OutputFlag::Carry,
            )
            .unwrap();
        (result, overflowed)
    };
    let executor = CpuFunctionExecutor::new(&func);
    extensive_trivial_default_overflowing_add_test(param, executor);
}

fn integer_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    default_overflowing_add_test(param, executor);
}

fn integer_extensive_trivial_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    extensive_trivial_default_overflowing_add_test(param, executor);
}

impl ExpectedNoiseLevels {
    fn after_unchecked_add(&mut self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> &Self {
        self.set_with(
            lhs.blocks
                .iter()
                .zip(rhs.blocks.iter())
                .map(|(a, b)| a.noise_level() + b.noise_level()),
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::ZERO, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..nb_tests {
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::ZERO, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..nb_tests {
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));

        clear = clear_0.wrapping_add(clear_1) % modulus;
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear, dec_res);

        // Add multiple times to raise the degree
        for _ in 0..nb_tests_smaller {
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
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

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

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
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

    for bit_size in 1..=64u32 {
        let num_blocks = bit_size.div_ceil(block_num_bits);
        let modulus = unsigned_modulus_u128(cks.parameters().message_modulus(), num_blocks);

        for _ in 0..50 {
            let clear_0 = rng.gen::<u128>() % modulus;
            let clear_1 = rng.gen::<u128>() % modulus;

            let ctxt_0 = sks.create_trivial_radix(clear_0, num_blocks as usize);
            let ctxt_1 = sks.create_trivial_radix(clear_1, num_blocks as usize);

            let ct_res = executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: u128 = cks.decrypt(&ct_res);

            let expected_clear = clear_0.wrapping_add(clear_1) % modulus;
            assert_eq!(
                expected_clear, dec_res,
                "Invalid result for {clear_0} + {clear_1}, expected: {expected_clear}, got: {dec_res}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
        }
    }
}

pub(crate) fn default_overflowing_add_test<P, T>(param: P, mut executor: T)
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

    let mut rng = rand::rng();

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

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_default_overflowing_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
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
    for bit_size in 1..=64u32 {
        let num_blocks = bit_size.div_ceil(block_num_bits);
        let modulus = unsigned_modulus_u128(cks.parameters().message_modulus(), num_blocks);

        for _ in 0..50 {
            let clear_0 = rng.gen::<u128>() % modulus;
            let clear_1 = rng.gen::<u128>() % modulus;

            let ctxt_0 = sks.create_trivial_radix(clear_0, num_blocks as usize);
            let ctxt_1 = sks.create_trivial_radix(clear_1, num_blocks as usize);

            let (ct_res, o_res) = executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: u128 = cks.decrypt(&ct_res);
            let dec_overflow = cks.decrypt_bool(&o_res);

            let (expected_clear, expected_overflow) =
                overflowing_add_under_modulus(clear_0, clear_1, modulus);
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
