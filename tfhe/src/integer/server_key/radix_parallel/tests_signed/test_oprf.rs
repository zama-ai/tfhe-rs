use crate::integer::oprf::OprfServerKey;
use crate::integer::server_key::radix_parallel::tests_long_run::OpSequenceFunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_oprf::{
    internal_test_uniformity, setup_oprf_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuOprfExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::SignedRadixCiphertext;
use crate::shortint::parameters::*;
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
    let executor = CpuOprfExecutor::new(
        &OprfServerKey::par_generate_oblivious_pseudo_random_signed_integer_bounded,
    );
    oprf_uniformity_bounded_test(param, executor);
}

fn oprf_signed_uniformity_unbounded<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuOprfExecutor::new(&OprfServerKey::par_generate_oblivious_pseudo_random_signed_integer);
    oprf_uniformity_unbounded_test(param, executor);
}

pub fn oprf_uniformity_bounded_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> OpSequenceFunctionExecutor<(Seed, u64, u64), SignedRadixCiphertext>,
{
    let cks = setup_oprf_test(param, &mut executor);

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
    E: for<'a> OpSequenceFunctionExecutor<(Seed, u64), SignedRadixCiphertext>,
{
    let cks = setup_oprf_test(param, &mut executor);

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
