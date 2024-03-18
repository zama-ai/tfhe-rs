use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_overflowing_scalar_add_test, signed_default_scalar_add_test,
    signed_unchecked_scalar_add_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_signed_unchecked_scalar_add);
create_parametrized_test!(integer_signed_default_scalar_add);
create_parametrized_test!(integer_signed_default_overflowing_scalar_add);

fn integer_signed_unchecked_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_add);
    signed_unchecked_scalar_add_test(param, executor);
}

fn integer_signed_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    signed_default_scalar_add_test(param, executor);
}

fn integer_signed_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_add_parallelized);
    signed_default_overflowing_scalar_add_test(param, executor);
}
