use crate::core_crypto::commons::math::random::tests::{
    cumulate, dkw_alpha_from_epsilon, sup_diff,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use statrs::distribution::ContinuousCDF;
use std::collections::HashMap;
use std::sync::Arc;
use tfhe_csprng::seeders::Seed;

create_parameterized_test!(oprf_uniformity_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});
create_parameterized_test!(oprf_any_range_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});
create_parameterized_test!(oprf_almost_uniformity_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});

fn oprf_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_integer_bounded,
    );
    oprf_uniformity_test(param, executor);
}

fn oprf_any_range_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_any_range_test(param, executor);
}

fn oprf_almost_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(
        &ServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_almost_uniformity_test(param, executor);
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

pub fn oprf_uniformity_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(Seed, u64, u64), RadixCiphertext>,
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
        let img: RadixCiphertext =
            executor.execute((Seed(seed as u128), random_bits_count, num_blocks as u64));
        cks.decrypt(&img)
    });
}

pub fn oprf_any_range_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let num_loops = 100;

    for s in 0..num_loops {
        let seed = Seed(s);

        for num_input_random_bits in [1, 2, 63, 64] {
            for (excluded_upper_bound, num_blocks_output) in [(3, 1), (3, 32), ((1 << 32) + 1, 64)]
            {
                let img = executor.execute((
                    seed,
                    num_input_random_bits,
                    excluded_upper_bound,
                    num_blocks_output as u64,
                ));

                assert_eq!(img.blocks.len(), num_blocks_output);

                let decrypted: u64 = cks.decrypt(&img);

                assert!(decrypted < excluded_upper_bound);
            }
        }
    }
}

pub fn oprf_almost_uniformity_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    let sample_count: usize = 10_000;
    let p_value_limit: f64 = 0.001;
    let num_input_random_bits: u64 = 4;
    let num_blocks_output = 64;
    let excluded_upper_bound = 10;
    let random_input_upper_bound = 1 << num_input_random_bits;

    let mut density = vec![0_usize; excluded_upper_bound as usize];
    for i in 0..random_input_upper_bound {
        let index = ((i * excluded_upper_bound) as f64 / random_input_upper_bound as f64) as usize;
        density[index] += 1;
    }

    let theoretical_pdf: Vec<f64> = density
        .iter()
        .map(|count| *count as f64 / random_input_upper_bound as f64)
        .collect();

    let values: Vec<u64> = (0..sample_count)
        .map(|seed| {
            let img = executor.execute((
                Seed(seed as u128),
                num_input_random_bits,
                excluded_upper_bound as u64,
                num_blocks_output,
            ));
            cks.decrypt(&img)
        })
        .collect();

    let mut bins = vec![0_u64; excluded_upper_bound as usize];
    for value in values {
        bins[value as usize] += 1;
    }

    let cumulative_bins = cumulate(&bins);
    let theoretical_cdf = cumulate(&theoretical_pdf);
    let sup_diff = sup_diff(&cumulative_bins, &theoretical_cdf);
    let p_value_upper_bound = dkw_alpha_from_epsilon(sample_count as f64, sup_diff);

    assert!(p_value_limit < p_value_upper_bound);
}
