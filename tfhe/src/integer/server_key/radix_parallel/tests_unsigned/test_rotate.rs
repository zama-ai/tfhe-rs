use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_rotate_left_test, default_rotate_right_test, unchecked_rotate_left_test,
    unchecked_rotate_right_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_unchecked_rotate_right);

create_parameterized_test!(integer_unchecked_rotate_left);

create_parameterized_test!(integer_rotate_right);

create_parameterized_test!(integer_rotate_left);

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    unchecked_rotate_right_test(param, executor);
}

fn integer_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    default_rotate_right_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    unchecked_rotate_left_test(param, executor);
}

fn integer_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    default_rotate_left_test(param, executor);
}
