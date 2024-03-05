use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_sub_test, default_sub_test, smart_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use crate::shortint::PBSParameters;

create_parametrized_test!(integer_smart_sub);
create_parametrized_test!(integer_default_sub);
create_parametrized_test!(integer_default_overflowing_sub);
create_parametrized_test!(
    integer_default_sub_work_efficient {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // This algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);

//=============================================================================
// Smart Tests
//=============================================================================
fn integer_smart_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_sub_parallelized);
    smart_sub_test(param, executor);
}

//=============================================================================
// Default Tests
//=============================================================================
fn integer_default_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    default_sub_test(param, executor);
}

fn integer_default_overflowing_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    default_overflowing_sub_test(param, executor);
}

fn integer_default_sub_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized_work_efficient);
    default_sub_test(param, executor);
}
