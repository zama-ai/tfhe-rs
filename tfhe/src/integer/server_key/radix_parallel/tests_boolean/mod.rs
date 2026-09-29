use crate::integer::prelude::*;
use crate::integer::server_key::radix_parallel::test_harness::{
    ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::{TestParameters, *};

#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;

pub(crate) fn test_boolean_flip_test_case<E>(ctxt: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, BooleanBlock, BooleanBlock), (BooleanBlock, BooleanBlock)>,
{
    let bits_per_block = ctxt.bits_per_block();
    TestBuilder::new(ctxt)
        .block_counts(vec![1])
        // Only fixed_cases because we test the whole truth table
        .fixed_cases(move |bit_count| {
            assert_eq!(
                bit_count, bits_per_block,
                "BooleanBlock tests should only be 0-block"
            );
            vec![
                (false, false, false),
                (false, false, true),
                (false, true, false),
                (false, true, true),
                (true, false, false),
                (true, false, true),
                (true, true, false),
                (true, true, true),
            ]
        })
        .execute(
            executor,
            |(condition, lhs, rhs)| {
                if condition {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn test_boolean_flip(params: impl Into<TestParameters>) {
    let ctx = TestContext::from_env(params);
    // Help the compiler
    let func = |sks: &ServerKey,
                c: &BooleanBlock,
                l: &BooleanBlock,
                r: &BooleanBlock|
     -> (BooleanBlock, BooleanBlock) { sks.flip_parallelized(c, l, r) };
    let mut executor = CpuFunctionExecutor::new(func);
    executor.setup_with_server_key(ctx.server_key());
    test_boolean_flip_test_case(&ctx, executor);
}

create_parameterized_test!(test_boolean_flip);
