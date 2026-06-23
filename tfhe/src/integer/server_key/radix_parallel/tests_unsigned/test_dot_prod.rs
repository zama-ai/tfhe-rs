use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, panic_if_any_block_is_not_clean_or_trivial, unsigned_modulus,
    CpuFunctionExecutor, MAX_VEC_LEN, NB_CTXT,
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

create_parameterized_test!(boolean_one_hot_dot_prod);

fn boolean_one_hot_dot_prod(params: impl Into<TestParameters>) {
    let executor = CpuFunctionExecutor::new(&ServerKey::boolean_one_hot_dot_prod);
    default_boolean_one_hot_dot_prod_test_case(params, executor);
}

pub(crate) fn default_boolean_one_hot_dot_prod_test_case<P, E>(params: P, mut dot_prod_executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [BooleanBlock], &'a [RadixCiphertext]), RadixCiphertext>,
{
    let params = params.into();
    let nb_tests = nb_tests_smaller_for_params(params);
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    dot_prod_executor.setup(&cks, sks.clone());

    // The result has the same number of blocks as the (radix) inputs, i.e. NB_CTXT.
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    for _ in 0..nb_tests {
        let vector_size = rng.gen_range(1..MAX_VEC_LEN);

        // 'one-hot': at most one boolean encrypts a `true`
        let hot_index = if rng.gen_bool(0.5) {
            Some(rng.gen_range(0..vector_size))
        } else {
            None
        };
        let clear_booleans = (0..vector_size)
            .map(|i| hot_index == Some(i))
            .collect::<Vec<_>>();
        let clear_values = (0..vector_size)
            .map(|_| rng.gen_range(0..modulus))
            .collect::<Vec<_>>();

        let mut e_booleans = clear_booleans
            .iter()
            .map(|&b| cks.encrypt_bool(b))
            .collect::<Vec<_>>();
        let mut e_values = clear_values
            .iter()
            .map(|&v| cks.encrypt(v))
            .collect::<Vec<_>>();

        // Corrupt one boolean block, preserving the logical (one-hot) value, so the
        // default op has to clean its boolean inputs.
        if let Some(hot) = hot_index {
            // Replace the single `true` block with a non-clean, non-zero (possibly
            // non-boolean) encryption. Cleaning maps it back to `true`.
            let non_zero = rng.gen_range(1..sks.message_modulus().0);
            e_booleans[hot] = BooleanBlock(cks.encrypt_one_block(non_zero));
        } else {
            // All-false: just raise the noise of some block (value stays `false`).
            let index = rng.gen_range(0..e_booleans.len());
            e_booleans[index].0.set_noise_level(
                NoiseLevel::NOMINAL + NoiseLevel(1),
                params.max_noise_level(),
            );
        }

        // Corrupt one radix input by leaving non-empty carries (value is unchanged), so
        // the default op has to clean its radix inputs before computing.
        {
            let index = rng.gen_range(0..e_values.len());
            sks.unchecked_scalar_add_assign(&mut e_values[index], 1u64);
            sks.unchecked_scalar_sub_assign(&mut e_values[index], 1u64);
        }

        let e_result = dot_prod_executor.execute((&e_booleans, &e_values));

        let result: u64 = cks.decrypt(&e_result);
        let expected_result = hot_index.map_or(0, |i| clear_values[i]);

        assert_eq!(
            result, expected_result,
            "Wrong result for boolean_one_hot_dot_prod:\n\
            Inputs: {clear_booleans:?}, {clear_values:?}\n\
            modulus: {modulus}\n\
            Expected: {expected_result}, got {result}
            "
        );

        panic_if_any_block_is_not_clean_or_trivial(&e_result, &cks);

        let e_result2 = dot_prod_executor.execute((&e_booleans, &e_values));
        assert_eq!(e_result2, e_result, "Failed determinism check");
    }
}
