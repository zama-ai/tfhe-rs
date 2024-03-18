use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_overflowing_scalar_sub_test, signed_unchecked_scalar_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_signed_unchecked_scalar_sub);
create_parametrized_test!(integer_signed_default_overflowing_scalar_sub);

fn integer_signed_unchecked_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_sub);
    signed_unchecked_scalar_sub_test(param, executor);
}

fn integer_signed_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_sub_parallelized);
    signed_default_overflowing_scalar_sub_test(param, executor);
}
