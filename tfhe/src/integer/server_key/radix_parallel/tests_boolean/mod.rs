use crate::integer::prelude::*;
use crate::integer::server_key::radix_parallel::test_harness::{
    ExecuteOn, RadixInputSize, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::{TestParameters, *};

pub(crate) fn test_boolean_flip_test_case<E>(ctxt: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, BooleanBlock, BooleanBlock), (BooleanBlock, BooleanBlock)>,
{
    TestBuilder::new(ctxt)
        .input_sizes(vec![RadixInputSize::new(1)])
        // Only fixed_cases because we test the whole truth table
        .fixed_cases_only()
        .fixed_cases(move |input_size, _ctx| {
            assert_eq!(
                input_size.n_blocks, 1,
                "BooleanBlock tests should only be 1-block"
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
