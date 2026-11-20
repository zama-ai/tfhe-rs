use crate::integer::keycache::KEY_CACHE;
use crate::integer::prelude::*;
use crate::integer::server_key::radix_parallel::test_harness::{
    condition_radix_pair_fixed_cases, condition_radix_scalar_fixed_cases,
    condition_scalar_radix_fixed_cases, scalar_if_then_else_fixed_cases, selected_scalar_cases,
    with_both_conditions, ExecuteOn, NumBlocks, RadixInputSize, TestBuilder, TestContext,
    TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_if_then_else);
create_parameterized_test!(integer_signed_default_if_then_else);
create_parameterized_test!(integer_signed_default_left_scalar_if_then_else);
create_parameterized_test!(integer_signed_default_right_scalar_if_then_else);
create_parameterized_test!(integer_signed_default_right_scalar_if_then_else_narrow_i8);
create_parameterized_test!(integer_signed_default_scalar_if_then_else);
create_parameterized_test!(integer_signed_default_scalar_if_then_else_narrow_i8);
create_parameterized_test!(integer_signed_default_flip);
create_parameterized_test!(integer_signed_default_left_scalar_flip);
create_parameterized_test!(integer_signed_default_right_scalar_flip);
create_parameterized_test!(integer_signed_default_right_scalar_flip_narrow_i8);

fn integer_signed_unchecked_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_if_then_else_parallelized);
    signed_unchecked_if_then_else_test(param, executor);
}

fn integer_signed_default_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func =
        |sks: &ServerKey,
         cond: &BooleanBlock,
         lhs: &SignedRadixCiphertext,
         rhs: &SignedRadixCiphertext| { sks.if_then_else_parallelized(cond, lhs, rhs) };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_if_then_else_test(&ctx, executor);
}

pub(crate) fn signed_default_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, SignedRadixCiphertext, SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_pair_fixed_cases::<Int>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Int, Int)| {
                if cond {
                    lhs
                } else {
                    rhs
                }
            },
        );
}

fn integer_signed_default_left_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: i64, rhs: &SignedRadixCiphertext| {
        sks.if_then_else_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_left_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn signed_default_left_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, i64, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_scalar_radix_fixed_cases::<i64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, TestScalar<i64>, Int)| {
                // The scalar is taken as its two's complement bits on the radix width
                if cond {
                    lhs.cast(rhs.bits())
                } else {
                    rhs
                }
            },
        );
}

fn integer_signed_default_right_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &SignedRadixCiphertext, rhs: i64| {
        sks.if_then_else_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_right_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn signed_default_right_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_scalar_fixed_cases::<i64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Int, TestScalar<i64>)| {
                if cond {
                    lhs
                } else {
                    rhs.cast(lhs.bits())
                }
            },
        );
}

fn integer_signed_default_right_scalar_if_then_else_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &SignedRadixCiphertext, rhs: i8| {
        sks.if_then_else_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_right_scalar_if_then_else_test(&ctx, executor);
}

/// Cases for the selections with a scalar narrower than the radix: the `i8` bounds, one and
/// minus one under both conditions, each against one of the radix bounds, zero and minus one.
///
/// Only the scalar decides whether a sign extension is needed, a negative scalar zero extended
/// turns `-1i8` into `255` on any radix wider than 8 bits.
fn condition_narrow_scalar_cases(
    input_size: RadixInputSize,
    ctx: &TestContext,
) -> Vec<(bool, Int, TestScalar<i8>)> {
    let radix_bits = ctx.radix_bits(input_size.n_blocks);
    let cases = [
        (Int::min(radix_bits), i8::MIN),
        (Int::max(radix_bits), -1),
        (Int::zero(radix_bits), 1),
        (Int::new(-1, radix_bits), i8::MAX),
    ]
    .map(|(radix, scalar)| {
        (
            radix,
            TestScalar::<i8>::new(Int::new(scalar.into(), i8::BITS)),
        )
    })
    .to_vec();
    with_both_conditions(cases)
}

/// Only the cases a scalar narrower than the radix adds, see
/// [`condition_narrow_scalar_cases`].
pub(crate) fn narrow_scalar_right_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, SignedRadixCiphertext, i8), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: signed_default_right_scalar_if_then_else_test already draws random
        // inputs, this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(condition_narrow_scalar_cases)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Int, TestScalar<i8>)| {
                if cond {
                    lhs
                } else {
                    rhs.cast(lhs.bits())
                }
            },
        );
}

fn integer_signed_default_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey,
                cond: &BooleanBlock,
                lhs: i64,
                rhs: i64,
                num_blocks: usize|
     -> SignedRadixCiphertext {
        sks.scalar_if_then_else_parallelized(cond, lhs, rhs, num_blocks)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, i64, i64, usize), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(scalar_if_then_else_fixed_cases::<i64>)
        .execute(
            executor,
            |(cond, lhs, rhs, num_blocks): (bool, TestScalar<i64>, TestScalar<i64>, NumBlocks)| {
                if cond {
                    lhs.cast(num_blocks.bits())
                } else {
                    rhs.cast(num_blocks.bits())
                }
            },
        );
}

fn integer_signed_default_scalar_if_then_else_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey,
                cond: &BooleanBlock,
                lhs: i8,
                rhs: i8,
                num_blocks: usize|
     -> SignedRadixCiphertext {
        sks.scalar_if_then_else_parallelized(cond, lhs, rhs, num_blocks)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_scalar_if_then_else_test(&ctx, executor);
}

/// Only the cases scalars narrower than the radix add: the `i8` bounds, one and minus one, a
/// negative scalar being sign extended over the radix width.
pub(crate) fn narrow_scalar_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, i8, i8, usize), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: signed_default_scalar_if_then_else_test already draws random inputs,
        // this test only adds the edges of scalars narrower than the radix
        .fixed_cases_only()
        .fixed_cases(|input_size, ctx| {
            let scalars = [i8::MIN, -1, 1, i8::MAX]
                .map(|scalar| TestScalar::<i8>::new(Int::new(scalar.into(), i8::BITS)));
            selected_scalar_cases(&scalars, NumBlocks::new(input_size, ctx))
        })
        .execute(
            executor,
            |(cond, lhs, rhs, num_blocks): (bool, TestScalar<i8>, TestScalar<i8>, NumBlocks)| {
                if cond {
                    lhs.cast(num_blocks.bits())
                } else {
                    rhs.cast(num_blocks.bits())
                }
            },
        );
}

fn integer_signed_default_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func =
        |sks: &ServerKey,
         cond: &BooleanBlock,
         lhs: &SignedRadixCiphertext,
         rhs: &SignedRadixCiphertext| { sks.flip_parallelized(cond, lhs, rhs) };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_flip_test(&ctx, executor);
}

pub(crate) fn signed_default_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, SignedRadixCiphertext, SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_pair_fixed_cases::<Int>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Int, Int)| {
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn integer_signed_default_left_scalar_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: i64, rhs: &SignedRadixCiphertext| {
        sks.flip_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_left_scalar_flip_test(&ctx, executor);
}

pub(crate) fn signed_default_left_scalar_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, i64, SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_scalar_radix_fixed_cases::<i64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, TestScalar<i64>, Int)| {
                let lhs = lhs.cast(rhs.bits());
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn integer_signed_default_right_scalar_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &SignedRadixCiphertext, rhs: i64| {
        sks.flip_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_right_scalar_flip_test(&ctx, executor);
}

pub(crate) fn signed_default_right_scalar_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_scalar_fixed_cases::<i64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Int, TestScalar<i64>)| {
                let rhs = rhs.cast(lhs.bits());
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn integer_signed_default_right_scalar_flip_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &SignedRadixCiphertext, rhs: i8| {
        sks.flip_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_right_scalar_flip_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see
/// [`condition_narrow_scalar_cases`].
pub(crate) fn narrow_scalar_right_scalar_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, SignedRadixCiphertext, i8),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: signed_default_right_scalar_flip_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(condition_narrow_scalar_cases)
        .execute(executor, |(cond, lhs, rhs): (bool, Int, TestScalar<i8>)| {
            let rhs = rhs.cast(lhs.bits());
            if cond {
                (rhs, lhs)
            } else {
                (lhs, rhs)
            }
        });
}

pub(crate) fn signed_unchecked_if_then_else_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as i64 / 2;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;
        let clear_condition = rng.gen_bool(0.5);

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);
        let ctxt_condition = cks.encrypt_bool(clear_condition);

        let ct_res = executor.execute((&ctxt_condition, &ctxt_0, &ctxt_1));

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, if clear_condition { clear_0 } else { clear_1 });
    }
}
