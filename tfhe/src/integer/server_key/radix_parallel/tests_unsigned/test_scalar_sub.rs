use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_sub_test, default_scalar_sub_test, smart_scalar_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_default_scalar_sub);
create_parametrized_test!(integer_default_overflowing_scalar_sub);

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_sub_parallelized);
    smart_scalar_sub_test(param, executor);
}

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    default_scalar_sub_test(param, executor);
}

fn integer_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);
    default_overflowing_scalar_sub_test(param, executor);
}
