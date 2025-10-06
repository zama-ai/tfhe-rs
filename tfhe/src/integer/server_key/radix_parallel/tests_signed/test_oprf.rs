use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
use crate::shortint::parameters::*;
use statrs::distribution::ContinuousCDF;
use std::collections::HashMap;
use std::sync::Arc;
use tfhe_csprng::seeders::Seed;

create_parameterized_test!(oprf_signed_uniformity_bounded {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_parameterized_test!(oprf_signed_uniformity_unbounded {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn oprf_signed_uniformity_bounded<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_signed_integer_bounded,
    );
    oprf_uniformity_bounded_test(param, executor);
}

fn oprf_signed_uniformity_unbounded<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::par_generate_oblivious_pseudo_random_signed_integer);
    oprf_uniformity_unbounded_test(param, executor);
}

fn square(a: f64) -> f64 {
    a * a
}

fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
where
    F: FnMut(usize) -> u64,
{
    let values: Vec<_> = (0..sample_count).map(f).collect();
    let mut values_count = HashMap::new();
    for i in &values {
        *values_count.entry(i).or_insert(0) += 1;
    }

    let single_expected_count = sample_count as f64 / distinct_values as f64;

    let distance: f64 = (0..distinct_values)
        .map(|value| *values_count.get(&value).unwrap_or(&0))
        .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
        .sum();

    statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
        .unwrap()
        .sf(distance)
}

fn internal_test_uniformity<F>(sample_count: usize, p_value_limit: f64, distinct_values: u64, f: F)
where
    F: FnMut(usize) -> u64,
{
    let p_value = uniformity_p_value(f, sample_count, distinct_values);
    assert!(
        p_value_limit < p_value,
        "p_value (={p_value}) expected to be bigger than {p_value_limit}"
    );
}

pub fn oprf_uniformity_bounded_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(Seed, u64, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let sample_count: usize = 10_000;
    let p_value_limit: f64 = 0.000_01;
    let random_bits_count = 3;
    let num_blocks = 2;
    let distinct_values = 1u64 << random_bits_count;

    internal_test_uniformity(sample_count, p_value_limit, distinct_values, |seed| {
        let img: SignedRadixCiphertext =
            executor.execute((Seed(seed as u128), random_bits_count, num_blocks as u64));
        let result = cks.decrypt_signed::<i64>(&img);
        assert!(result >= 0);
        result as u64
    });
}

pub fn oprf_uniformity_unbounded_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(Seed, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let sample_count: usize = 10_000;
    let p_value_limit: f64 = 0.000_01;
    let num_blocks = 2;
    let total_bits = cks.parameters().message_modulus().0.ilog2() * num_blocks;

    let distinct_values = 1u64 << total_bits;
    let offset = 1u64 << (total_bits - 1);

    internal_test_uniformity(sample_count, p_value_limit, distinct_values, |seed| {
        let img: SignedRadixCiphertext = executor.execute((Seed(seed as u128), num_blocks as u64));
        let decrypted = cks.decrypt_signed::<i64>(&img);
        (decrypted as i64 + offset as i64) as u64
    });
}
