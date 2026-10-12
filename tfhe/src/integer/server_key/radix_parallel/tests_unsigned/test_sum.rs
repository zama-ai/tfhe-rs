use crate::integer::server_key::radix_parallel::test_harness::{
    vec_size_requirements, ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_default_unsigned_overflowing_sum_ciphertexts_vec);
create_parameterized_test!(integer_default_sum_ciphertexts_vec);

/// Vector lengths both sum tests cover.
const VEC_LENS: [u32; 8] = [0, 1, 2, 15, 16, 17, 64, 65];

fn integer_default_unsigned_overflowing_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    // Same inference problem as in `integer_default_sum_ciphertexts_vec`
    let overflowing_sum_vec =
        |sks: &ServerKey, ctxts: &[RadixCiphertext]| -> Option<(RadixCiphertext, BooleanBlock)> {
            sks.unsigned_overflowing_sum_ciphertexts_parallelized(ctxts)
        };
    let mut executor = CpuFunctionExecutor::new(overflowing_sum_vec);
    executor.setup_with_server_key(ctx.server_key());
    default_unsigned_overflowing_sum_ciphertexts_vec_test(&ctx, executor);
}

pub(crate) fn default_unsigned_overflowing_sum_ciphertexts_vec_test<E>(
    ctx: &TestContext,
    executor: E,
) where
    E: ExecuteOn<(Vec<RadixCiphertext>,), Option<(RadixCiphertext, BooleanBlock)>>,
{
    // Same lengths as `default_sum_ciphertexts_vec_test`
    TestBuilder::new(ctx)
        .size_requirements(vec_size_requirements(ctx, VEC_LENS))
        .n_random(2)
        .execute(executor, |(clears,): (Vec<Uint>,)| {
            let bits = clears.first()?.bits();
            let mut overflowed = false;
            let sum = clears.iter().copied().fold(Uint::zero(bits), |acc, clear| {
                let (sum, overflow) = acc.overflowing_add(clear);
                overflowed |= overflow;
                sum
            });
            Some((sum, overflowed))
        });
}

fn integer_default_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &ServerKey, ctxts: &[RadixCiphertext]| -> Option<RadixCiphertext> {
        sks.sum_ciphertexts_parallelized(ctxts)
    };
    let mut executor = CpuFunctionExecutor::new(sum_vec);
    executor.setup_with_server_key(ctx.server_key());
    default_sum_ciphertexts_vec_test(&ctx, executor);
}

pub(crate) fn default_sum_ciphertexts_vec_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(Vec<RadixCiphertext>,), Option<RadixCiphertext>>,
{
    TestBuilder::new(ctx)
        .size_requirements(vec_size_requirements(ctx, VEC_LENS))
        .n_random(2)
        .execute(executor, |(clears,): (Vec<Uint>,)| {
            let bits = clears.first()?.bits();
            Some(
                clears
                    .iter()
                    .copied()
                    .fold(Uint::zero(bits), Uint::wrapping_add),
            )
        });
}
