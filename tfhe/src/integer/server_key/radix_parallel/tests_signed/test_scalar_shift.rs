use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_scalar_left_shift_test, signed_default_scalar_right_shift_test,
    signed_unchecked_scalar_left_shift_test, signed_unchecked_scalar_right_shift_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_signed_unchecked_scalar_left_shift);
create_parametrized_test!(integer_signed_default_scalar_left_shift);
create_parametrized_test!(integer_signed_unchecked_scalar_right_shift);
create_parametrized_test!(integer_signed_default_scalar_right_shift);

fn integer_signed_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    signed_unchecked_scalar_left_shift_test(param, executor);
}

fn integer_signed_default_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    signed_default_scalar_left_shift_test(param, executor);
}

fn integer_signed_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    signed_unchecked_scalar_right_shift_test(param, executor);
}

fn integer_signed_default_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    signed_default_scalar_right_shift_test(param, executor);
}
