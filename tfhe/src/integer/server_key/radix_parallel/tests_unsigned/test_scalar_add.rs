use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, RadixInputSize, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    narrow_scalar_cases, CpuFunctionExecutor,
};
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
create_parameterized_test!(integer_default_scalar_add_u8);
create_parameterized_test!(integer_default_scalar_add_i8);
create_parameterized_test!(integer_default_overflowing_scalar_add);
create_parameterized_test!(integer_default_overflowing_scalar_add_u8);
create_parameterized_test!(integer_default_overflowing_scalar_add_i8);
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
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_scalar_add_test(&ctx, executor);
}

pub(crate) fn default_overflowing_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            // The overflow is that of the exact sum, the scalar may exceed the radix
            lhs.overflowing_scalar_add(rhs.clear())
        });
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
fn signed_scalar_on_unsigned_radix_cases(
    input_size: RadixInputSize,
    ctx: &TestContext,
) -> Vec<(Uint, TestScalar<i64>)> {
    let radix_bits = ctx.radix_bits(input_size.n_blocks);
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
        .fixed_cases(signed_scalar_on_unsigned_radix_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<i64>)| {
            overflowing_add_signed_scalar(lhs, rhs.clear().value())
        });
}

/// `lhs + scalar` on `lhs`'s width, with the overflow of the exact sum: adding a negative
/// scalar is subtracting its magnitude.
fn overflowing_add_signed_scalar(lhs: Uint, scalar: i128) -> (Uint, bool) {
    if scalar < 0 {
        lhs.overflowing_scalar_sub(Uint::new(scalar.unsigned_abs(), u128::BITS))
    } else {
        lhs.overflowing_scalar_add(Uint::new(scalar as u128, u128::BITS))
    }
}

fn integer_default_overflowing_scalar_add_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized::<u8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_overflowing_scalar_add_test(&ctx, executor);
}

/// Block counts for the tests of a scalar narrower than the radix: one block, the scalar's
/// width, one block past it and twice it.
fn narrow_scalar_input_sizes(ctx: &TestContext) -> Vec<RadixInputSize> {
    let scalar_width = u8::BITS.div_ceil(ctx.bits_per_block());
    [1, scalar_width, scalar_width + 1, 2 * scalar_width]
        .map(RadixInputSize::new)
        .to_vec()
}

/// Cases for a signed scalar narrower than the unsigned radix: the radix edges against the
/// `i8` bounds, one and minus one. A negative scalar has to be sign extended to the radix
/// width, a zero extension turns `-1i8` into `255` on any radix wider than 8 bits.
fn narrow_signed_scalar_on_unsigned_radix_cases(
    input_size: RadixInputSize,
    ctx: &TestContext,
) -> Vec<(Uint, TestScalar<i8>)> {
    let radix_bits = ctx.radix_bits(input_size.n_blocks);
    let scalars = [i8::MIN, -1, 1, i8::MAX]
        .map(|scalar| TestScalar::<i8>::new(Int::new(scalar.into(), i8::BITS)));
    let radix_edges = [
        Uint::zero(radix_bits),
        Uint::one(radix_bits),
        Uint::max(radix_bits),
    ];
    iproduct!(radix_edges, scalars).collect()
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_overflowing_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u8), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_overflowing_scalar_add_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u8>)| {
            lhs.overflowing_scalar_add(rhs.clear())
        });
}

fn integer_default_overflowing_scalar_add_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::overflowing_scalar_add_parallelized::<RadixCiphertext, i8>,
    );
    executor.setup_with_server_key(ctx.server_key());
    narrow_signed_scalar_overflowing_scalar_add_test(&ctx, executor);
}

/// Only the cases a signed scalar narrower than the radix adds, see
/// [`narrow_signed_scalar_on_unsigned_radix_cases`].
pub(crate) fn narrow_signed_scalar_overflowing_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, i8), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_overflowing_scalar_add_signed_scalar_test already draws random
        // inputs, this test only adds the edges of a signed scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_signed_scalar_on_unsigned_radix_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<i8>)| {
            overflowing_add_signed_scalar(lhs, rhs.clear().value())
        });
}

fn integer_default_scalar_add_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized::<RadixCiphertext, u8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_scalar_add_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u8), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_scalar_add_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u8>)| {
            lhs.wrapping_add(rhs.cast(lhs.bits()))
        });
}

fn integer_default_scalar_add_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized::<RadixCiphertext, i8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_signed_scalar_scalar_add_test(&ctx, executor);
}

/// Only the cases a signed scalar narrower than the radix adds, see
/// [`narrow_signed_scalar_on_unsigned_radix_cases`].
pub(crate) fn narrow_signed_scalar_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, i8), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_scalar_add_test and
        // default_overflowing_scalar_add_signed_scalar_test already draw random inputs,
        // this test only adds the edges of a signed scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_signed_scalar_on_unsigned_radix_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<i8>)| {
            // The scalar's two's complement bits, sign extended to the radix width
            lhs.wrapping_add(Uint::new(rhs.clear().value() as u128, lhs.bits()))
        });
}
