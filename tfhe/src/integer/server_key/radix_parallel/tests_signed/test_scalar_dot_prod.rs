use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::signed_add_under_modulus;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, unsigned_modulus, CpuFunctionExecutor, MAX_NB_CTXT, MAX_VEC_LEN,
    NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::{thread_rng, Rng};
use std::sync::Arc;

create_parameterized_test!(signed_unchecked_boolean_scalar_dot_prod);
create_parameterized_test!(signed_smart_boolean_scalar_dot_prod);
create_parameterized_test!(signed_boolean_scalar_dot_prod);

fn signed_unchecked_boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_boolean_scalar_dot_prod_parallelized);
    signed_unchecked_boolean_scalar_dot_prod_test_case(params, executor);
}

fn signed_smart_boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_boolean_scalar_dot_prod_parallelized);
    signed_smart_boolean_scalar_dot_prod_test_case(params, executor);
}

fn signed_boolean_scalar_dot_prod(params: impl Into<TestParameters>) {
    let executor = CpuFunctionExecutor::new(&ServerKey::boolean_scalar_dot_prod_parallelized);
    signed_default_boolean_scalar_dot_prod_test_case(params, executor);
}

fn boolean_dot_prod(bs: &[bool], cs: &[i64], modulus: i64) -> i64 {
    let mut r = 0i64;
    for (&b, &c) in bs.iter().zip(cs.iter()) {
        r = signed_add_under_modulus(r, i64::from(b) * c, modulus);
    }
    r
}

pub(crate) fn signed_unchecked_boolean_scalar_dot_prod_test_case<P, E>(
    params: P,
    mut dot_prod_executor: E,
) where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [BooleanBlock], &'a [i64], u32), SignedRadixCiphertext>,
{
    let params = params.into();
    let nb_tests = nb_tests_smaller_for_params(params);
    let (cks, sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    dot_prod_executor.setup(&cks, sks);

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus =
            unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32) as i64;
        let half_modulus = modulus / 2;
        if half_modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(-half_modulus..half_modulus))
                .collect::<Vec<_>>();

            let e_booleans = clear_booleans
                .iter()
                .map(|&b| cks.encrypt_bool(b))
                .collect::<Vec<_>>();

            let e_result =
                dot_prod_executor.execute((&e_booleans, &clear_values, num_blocks as u32));

            let result: i64 = cks.decrypt_signed(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, half_modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );
        }
    }
}

pub(crate) fn signed_smart_boolean_scalar_dot_prod_test_case<P, E>(
    params: P,
    mut dot_prod_executor: E,
) where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a mut [BooleanBlock], &'a [i64], u32), SignedRadixCiphertext>,
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
        let modulus =
            unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32) as i64;
        let half_modulus = modulus / 2;
        if half_modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let mut clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(-half_modulus..half_modulus))
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

            let result: i64 = cks.decrypt_signed(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, half_modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );
        }
    }
}

pub(crate) fn signed_default_boolean_scalar_dot_prod_test_case<P, E>(
    params: P,
    mut dot_prod_executor: E,
) where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [BooleanBlock], &'a [i64], u32), SignedRadixCiphertext>,
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
        let modulus =
            unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32) as i64;
        let half_modulus = modulus / 2;
        if half_modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let vector_size = rng.gen_range(1..MAX_VEC_LEN);

            let mut clear_booleans = (0..vector_size)
                .map(|_| rng.gen_bool(0.5))
                .collect::<Vec<_>>();
            let clear_values = (0..vector_size)
                .map(|_| rng.gen_range(-half_modulus..half_modulus))
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

            let result: i64 = cks.decrypt_signed(&e_result);
            let expected_result = boolean_dot_prod(&clear_booleans, &clear_values, half_modulus);

            assert_eq!(
                result, expected_result,
                "Wrong result for boolean_scalar_dot_prod:\n\
                Inputs: {clear_booleans:?}, {clear_values:?}, num_blocks: {num_blocks}\n\
                modulus: {modulus}\n\
                Expected: {expected_result}, got {result}
                "
            );

            let e_result2 =
                dot_prod_executor.execute((&e_booleans, &clear_values, num_blocks as u32));
            assert_eq!(e_result2, e_result, "Failed determinism check");
        }
    }
}
