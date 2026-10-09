use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::default_overflowing_scalar_add_test;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use itertools::iproduct;

create_parameterized_test!(integer_default_scalar_add);
create_parameterized_test!(integer_default_overflowing_scalar_add);
create_parameterized_test!(integer_default_overflowing_scalar_add_signed_scalar);

fn integer_default_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_add_test(&ctx, executor);
}

pub(crate) fn default_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            // The scalar is reduced to the radix width
            lhs.wrapping_add(rhs.cast(lhs.bits()))
        });
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    default_overflowing_scalar_add_test(param, executor);
}

/// The generic overflowing scalar add also accepts a signed scalar on an unsigned radix.
fn integer_default_overflowing_scalar_add_signed_scalar<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::overflowing_scalar_add_parallelized::<RadixCiphertext, i64>,
    );
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_scalar_add_signed_scalar_test(&ctx, executor);
}

/// Cases for a signed scalar on an unsigned radix of `radix_bits` bits: the radix edges
/// against zero, one, the radix maximum and just past it, the negatives whose low
/// `radix_bits` bits are all set (-1) or all clear (-2ⁿ), just past them, and the scalar
/// type bounds.
fn signed_scalar_on_unsigned_radix_cases(radix_bits: u32) -> Vec<(Uint, TestScalar<i64>)> {
    let mut scalars: Vec<i128> = vec![0, 1, -1, -2, i128::from(i64::MIN), i128::from(i64::MAX)];
    if radix_bits < i64::BITS {
        let two_pow_radix_bits = 1i128 << radix_bits;
        scalars.extend([
            two_pow_radix_bits - 1,
            two_pow_radix_bits,
            two_pow_radix_bits + 1,
            -(two_pow_radix_bits - 1),
            -two_pow_radix_bits,
            -two_pow_radix_bits - 1,
            -two_pow_radix_bits - 2,
        ]);
    }
    scalars.sort_unstable();
    scalars.dedup();
    let scalars: Vec<TestScalar<i64>> = scalars
        .into_iter()
        .map(|scalar| TestScalar::new(Int::new(scalar, i64::BITS)))
        .collect();
    let radix_edges = [
        Uint::zero(radix_bits),
        Uint::one(radix_bits),
        Uint::max(radix_bits),
    ];
    iproduct!(radix_edges, scalars).collect()
}

pub(crate) fn default_overflowing_scalar_add_signed_scalar_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, i64), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(signed_scalar_on_unsigned_radix_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<i64>)| {
            // Adding a negative scalar is subtracting its magnitude
            let scalar = rhs.clear().value();
            if scalar < 0 {
                lhs.overflowing_scalar_sub(Uint::new(scalar.unsigned_abs(), u128::BITS))
            } else {
                lhs.overflowing_scalar_add(Uint::new(scalar as u128, u128::BITS))
            }
        });
}
