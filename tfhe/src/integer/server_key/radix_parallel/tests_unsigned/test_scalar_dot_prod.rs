use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, panic_if_any_block_is_not_clean_or_trivial,
    panic_if_any_block_values_exceeds_its_degree, unsigned_modulus, CpuFunctionExecutor,
    MAX_NB_CTXT, MAX_VEC_LEN, NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::TestParameters;
use rand::{thread_rng, Rng};
use std::sync::Arc;

#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(unchecked_boolean_scalar_dot_prod);
create_parameterized_test!(smart_boolean_scalar_dot_prod);
create_parameterized_test!(boolean_scalar_dot_prod);

fn unchecked_boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_boolean_scalar_dot_prod_parallelized);
    unchecked_boolean_scalar_dot_prod_test_case(params, executor);
}

fn smart_boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_boolean_scalar_dot_prod_parallelized);
    smart_boolean_scalar_dot_prod_test_case(params, executor);
}

fn boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor = CpuFunctionExecutor::new(&ServerKey::boolean_scalar_dot_prod_parallelized);
    default_boolean_scalar_dot_prod_test_case(params, executor);
}

fn boolean_dot_prod(bs: &[bool], cs: &[u64], modulus: u64) -> u64 {
    bs.iter()
        .zip(cs.iter())
        .map(|(&b, &c)| u64::from(b) * c)
        .sum::<u64>()
        % modulus
}

pub(crate) fn unchecked_boolean_scalar_dot_prod_test_case<P, E>(params: P, mut dot_prod_executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [BooleanBlock], &'a [u64], u32), RadixCiphertext>,
{
    let params = params.into();
    let nb_tests = nb_tests_smaller_for_params(params);
    let (cks, sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    dot_prod_executor.setup(&cks, sks);

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(0..modulus))
                .collect::<Vec<_>>();

            let e_booleans = clear_booleans
                .iter()
                .map(|&b| cks.encrypt_bool(b))
                .collect::<Vec<_>>();

            let e_result =
                dot_prod_executor.execute((&e_booleans, &clear_values, num_blocks as u32));

            let result: u64 = cks.decrypt(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );

            panic_if_any_block_values_exceeds_its_degree(&e_result, &cks);
        }
    }
}

pub(crate) fn smart_boolean_scalar_dot_prod_test_case<P, E>(params: P, mut dot_prod_executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a mut [BooleanBlock], &'a [u64], u32), RadixCiphertext>,
{
    let params = params.into();
    let nb_tests = nb_tests_smaller_for_params(params);
    let (cks, sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    dot_prod_executor.setup(&cks, sks.clone());

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let mut clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(0..modulus))
                .collect::<Vec<_>>();

            let mut e_booleans = clear_booleans
                .iter()
                .map(|&b| cks.encrypt_bool(b))
                .collect::<Vec<_>>();

            {
                let index = rng.gen_range(0..e_booleans.len());
                if rng.gen_bool(0.5) {
                    e_booleans[index].0.set_noise_level(
                        NoiseLevel::NOMINAL + NoiseLevel(1),
                        params.max_noise_level(),
                    );
                } else {
                    let random_non_bool = rng.gen_range(0..sks.message_modulus().0);
                    e_booleans[index] = BooleanBlock(cks.encrypt_one_block(random_non_bool));
                    clear_booleans[index] = random_non_bool != 0;
                }
            }

            let e_result =
                dot_prod_executor.execute((&mut e_booleans, &clear_values, num_blocks as u32));

            let result: u64 = cks.decrypt(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );

            panic_if_any_block_values_exceeds_its_degree(&e_result, &cks);
        }
    }
}

pub(crate) fn default_boolean_scalar_dot_prod_test_case<P, E>(params: P, mut dot_prod_executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [BooleanBlock], &'a [u64], u32), RadixCiphertext>,
{
    let params = params.into();
    let nb_tests = nb_tests_smaller_for_params(params);
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    dot_prod_executor.setup(&cks, sks.clone());

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let mut clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(0..modulus))
                .collect::<Vec<_>>();

            let mut e_booleans = clear_booleans
                .iter()
                .map(|&b| cks.encrypt_bool(b))
                .collect::<Vec<_>>();

            {
                let index = rng.gen_range(0..e_booleans.len());
                if rng.gen_bool(0.5) {
                    e_booleans[index].0.set_noise_level(
                        NoiseLevel::NOMINAL + NoiseLevel(1),
                        params.max_noise_level(),
                    );
                } else {
                    let random_non_bool = rng.gen_range(0..sks.message_modulus().0);
                    e_booleans[index] = BooleanBlock(cks.encrypt_one_block(random_non_bool));
                    clear_booleans[index] = random_non_bool != 0;
                }
            }

            let e_result =
                dot_prod_executor.execute((&e_booleans, &clear_values, num_blocks as u32));

            let result: u64 = cks.decrypt(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );

            panic_if_any_block_is_not_clean_or_trivial(&e_result, &cks);

            let e_result2 =
                dot_prod_executor.execute((&e_booleans, &clear_values, num_blocks as u32));
            assert_eq!(e_result2, e_result, "Failed determinism check");
        }
    }
}
