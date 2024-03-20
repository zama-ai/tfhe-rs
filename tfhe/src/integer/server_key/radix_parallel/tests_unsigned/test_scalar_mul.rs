use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_mul_test, default_scalar_mul_u128_fix_non_reg_test, smart_scalar_mul_test,
    smart_scalar_mul_u128_fix_non_reg_test, unchecked_scalar_mul_corner_cases_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(
    integer_smart_scalar_mul_u128_fix_non_reg_test {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        },
        no_coverage => {
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        }
    }
);
create_parametrized_test!(integer_unchecked_scalar_mul_corner_cases);
create_parametrized_test!(
    integer_default_scalar_mul_u128_fix_non_reg_test {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        },
        no_coverage => {
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        }
    }
);
create_parametrized_test!(integer_smart_scalar_mul);
create_parametrized_test!(integer_default_scalar_mul);

fn integer_unchecked_scalar_mul_corner_cases<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    unchecked_scalar_mul_corner_cases_test(param, executor);
}

fn integer_smart_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_mul_parallelized);
    smart_scalar_mul_test(param, executor);
}

fn integer_smart_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_mul_parallelized);
    smart_scalar_mul_u128_fix_non_reg_test(param, executor);
}

fn integer_default_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    default_scalar_mul_u128_fix_non_reg_test(param, executor);
}

fn integer_default_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    default_scalar_mul_test(param, executor);
}
