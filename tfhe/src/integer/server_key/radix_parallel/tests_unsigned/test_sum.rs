use crate::integer::server_key::radix_parallel::test_harness::{
    vec_size_requirements, ExecuteOn, SizeRequirements, TestBuilder, TestContext,
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

/// Random tests do not exercise the non overflow case a lot (ever?)
///
/// So we provide fixed cases that do not create a result that overflows
fn sum_boundary_fixed_cases(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(Vec<Uint>,)> {
    let vec_len = size_requirements
        .vec_len
        .expect("sum tests need SizeRequirements with a vec_len") as usize;
    if vec_len == 0 {
        // Nothing to choose, and the empty input is already covered by the random cases
        return vec![];
    }

    let bits = ctx.radix_bits(size_requirements.n_blocks);
    let max = Uint::max(bits);
    let vec_of_zeros = vec![Uint::zero(bits); vec_len];

    let mut cases = vec![vec_of_zeros.clone()];

    // Sum of a single one and many zeros and sum of single max value and many zeros
    for value in [Uint::one(bits), max] {
        let mut case = vec_of_zeros.clone();
        case[0] = value;
        cases.push(case);
    }

    if vec_len > 1 {
        // We want to sum many ones, but we have to make sure it won't overflow
        if vec_len as u128 <= max.value() {
            cases.push(vec![Uint::one(bits); vec_len]);
        }

        // Smallest overflow there is, one past the largest sum that fits
        let mut case = vec_of_zeros;
        case[0] = max;
        case[1] = Uint::one(bits);
        cases.push(case);
    }

    cases.into_iter().map(|clears| (clears,)).collect()
}

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
        .fixed_cases(sum_boundary_fixed_cases)
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
        .fixed_cases(sum_boundary_fixed_cases)
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
