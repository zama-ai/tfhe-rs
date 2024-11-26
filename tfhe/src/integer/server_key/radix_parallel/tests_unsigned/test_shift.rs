use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_left_shift_test, default_right_shift_test, unchecked_left_shift_test,
    unchecked_right_shift_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_unchecked_left_shift);

create_parameterized_test!(integer_unchecked_right_shift);
create_parameterized_test!(integer_left_shift);
create_parameterized_test!(integer_right_shift);

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    unchecked_right_shift_test(param, executor);
}

fn integer_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    default_right_shift_test(param, executor);
}

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    unchecked_left_shift_test(param, executor);
}

fn integer_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    default_left_shift_test(param, executor);
}
