use super::{
    nb_tests_for_params, nb_tests_smaller_for_params, overflowing_add_under_modulus,
    panic_if_any_block_info_exceeds_max_degree_or_noise,
    panic_if_any_block_values_exceeds_its_degree, unsigned_modulus, unsigned_modulus_u128,
    CpuFunctionExecutor, ExpectedDegrees, ExpectedNoiseLevels, NB_CTXT,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
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
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_add_test(&ctx, executor);
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
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
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
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_add_test(&ctx, executor);
}

fn integer_extensive_trivial_overflowing_advanced_add_assign_with_carry_at_least_4_bits<P>(param: P)
where
    P: Into<TestParameters>,
{
    // We explicitly call the 4 bit function to make sure it's being tested,
    // no matter the number of blocks / threads available
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
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
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
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
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_add_test(&ctx, executor);
}

fn integer_extensive_trivial_advanced_overflowing_add_assign_with_carry_sequential<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
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
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_add_test(&ctx, executor);
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

    let mut rng = rand::thread_rng();

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

    let mut rng = rand::thread_rng();

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

    let mut rng = rand::thread_rng();

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

pub(crate) fn default_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| lhs.wrapping_add(rhs));
}

pub(crate) fn default_overflowing_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| {
            lhs.overflowing_add(rhs)
        });
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

    let mut rng = rand::thread_rng();

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

    let mut rng = rand::thread_rng();

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
