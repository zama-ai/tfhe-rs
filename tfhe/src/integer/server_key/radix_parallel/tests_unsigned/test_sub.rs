use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::radix_parallel::test_harness::{
    radix_pair_fixed_cases, ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, overflowing_sub_under_modulus,
    panic_if_any_block_info_exceeds_max_degree_or_noise,
    panic_if_any_block_values_exceeds_its_degree, unsigned_modulus, unsigned_modulus_u128,
    CpuFunctionExecutor, ExpectedDegrees, ExpectedNoiseLevels,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_sub);
create_parameterized_test!(integer_default_sub);
create_parameterized_test!(integer_extensive_trivial_default_sub);
create_parameterized_test!(integer_default_overflowing_sub);
create_parameterized_test!(integer_extensive_trivial_default_overflowing_sub);
create_parameterized_test!(integer_advanced_sub_assign_with_borrow_at_least_4_bits {
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
create_parameterized_test!(integer_advanced_sub_assign_with_borrow_sequential);

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_sub);
    unchecked_sub_test(param, executor);
}

fn integer_default_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_sub_test(&ctx, executor);
}

fn integer_extensive_trivial_default_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    extensive_trivial_default_sub_test(param, executor);
}

fn integer_default_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_sub_test(&ctx, executor);
}

fn integer_extensive_trivial_default_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    extensive_trivial_default_overflowing_sub_test(param, executor);
}

fn integer_advanced_sub_assign_with_borrow_at_least_4_bits<P>(param: P)
where
    P: Into<TestParameters>,
{
    // We explicitly call the 4 bit function to make sure it's being tested,
    // no matter the number of blocks / threads available
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
        let overflowed = sks
            .advanced_sub_assign_with_borrow_parallelized_at_least_4_bits(
                &mut result,
                &rhs,
                None,
                true,
            )
            .expect("Overflow flag was requested");
        (result, overflowed)
    };
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_sub_test(&ctx, executor);
}

fn integer_advanced_sub_assign_with_borrow_sequential<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
        let mut result = lhs.clone();
        let rhs = sks.clean_for_default_binary_assign_op(&mut result, rhs);
        let overflowed = sks
            .advanced_sub_assign_with_borrow_sequential(&mut result, &rhs, None, true)
            .expect("Overflow flag was requested");
        (result, overflowed)
    };
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_sub_test(&ctx, executor);
}

impl ExpectedDegrees {
    fn after_unchecked_sub(&mut self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> &Self {
        let negated_rhs_degrees = NegatedDegreeIter::new(
            rhs.blocks
                .iter()
                .map(|block| (block.degree, block.message_modulus)),
        );
        self.set_with(
            lhs.blocks
                .iter()
                .zip(negated_rhs_degrees)
                .map(|(block, negated_rhs_degree)| block.degree + negated_rhs_degree),
        );
        self
    }
}

impl ExpectedNoiseLevels {
    fn after_unchecked_sub(&mut self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> &Self {
        // the noise level of rhs does not change after negation
        self.set_with(
            lhs.blocks
                .iter()
                .zip(rhs.blocks.iter())
                .map(|(a, b)| a.noise_level() + b.noise_level()),
        );
        self
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn unchecked_sub_test<P, T>(param: P, mut executor: T)
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

    let modulus = unsigned_modulus(
        cks.parameters().message_modulus(),
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT as u32,
    );

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    let mut expected_noise_levels = ExpectedNoiseLevels::new(
        NoiseLevel::ZERO,
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT,
    );
    let mut expected_degrees = ExpectedDegrees::new(
        Degree::new(0),
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT,
    );

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let encrypted_result = executor.execute((&ctxt_0, &ctxt_1));
        expected_noise_levels
            .after_unchecked_sub(&ctxt_0, &ctxt_1)
            .panic_if_any_is_not_equal(&encrypted_result);
        expected_degrees
            .after_unchecked_sub(&ctxt_0, &ctxt_1)
            .panic_if_any_is_not_equal(&encrypted_result);
        panic_if_any_block_values_exceeds_its_degree(&encrypted_result, &cks);
        panic_if_any_block_info_exceeds_max_degree_or_noise(
            &encrypted_result,
            max_degree,
            max_noise_level,
        );

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected_result = clear_0.wrapping_sub(clear_1) % modulus;
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid sub result, expected {clear_0} - {clear_1} \
            to be {expected_result}, but got {decrypted_result}."
        );
    }
}

//=============================================================================
// Default Tests
//=============================================================================

pub(crate) fn default_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Uint>)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| lhs.wrapping_sub(rhs));
}

pub(crate) fn default_overflowing_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Uint>)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| {
            lhs.overflowing_sub(rhs)
        });
}

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_default_sub_test<P, T>(param: P, mut sub_executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((
        cks,
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT,
    ));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    sub_executor.setup(&cks, sks.clone());

    let message_modulus = cks.parameters().message_modulus();
    let block_num_bits = message_modulus.0.ilog2();

    for bit_size in (1..=64u32).step_by(block_num_bits as usize) {
        let num_blocks = bit_size.div_ceil(block_num_bits);
        let modulus = unsigned_modulus_u128(cks.parameters().message_modulus(), num_blocks);

        for _ in 0..50 {
            let clear_0 = rng.gen::<u128>() % modulus;
            let clear_1 = rng.gen::<u128>() % modulus;

            let ctxt_0 = sks.create_trivial_radix(clear_0, num_blocks as usize);
            let ctxt_1 = sks.create_trivial_radix(clear_1, num_blocks as usize);

            let ct_res = sub_executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: u128 = cks.decrypt(&ct_res);

            let expected_clear = clear_0.wrapping_sub(clear_1) % modulus;
            assert_eq!(
                expected_clear, dec_res,
                "Invalid result for {clear_0} - {clear_1}, expected: {expected_clear}, got: {dec_res}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
        }
    }
}

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
pub(crate) fn extensive_trivial_default_overflowing_sub_test<P, T>(
    param: P,
    mut overflowing_sub_executor: T,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((
        cks,
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT,
    ));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    overflowing_sub_executor.setup(&cks, sks.clone());

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

            let (ct_res, o_res) = overflowing_sub_executor.execute((&ctxt_0, &ctxt_1));
            let dec_res: u128 = cks.decrypt(&ct_res);
            let dec_overflow = cks.decrypt_bool(&o_res);

            let (expected_clear, expected_overflow) =
                overflowing_sub_under_modulus(clear_0, clear_1, modulus);
            assert_eq!(
                expected_clear, dec_res,
                "Invalid result for {clear_0} - {clear_1}, expected: {expected_clear}, got: {dec_res}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
            assert_eq!(
                expected_overflow, dec_overflow,
                "Invalid overflow result for {clear_0} - {clear_1}, expected: {expected_overflow}, got: {dec_overflow}\n\
                    num_blocks={num_blocks}, modulus={modulus}"
            );
        }
    }
}
