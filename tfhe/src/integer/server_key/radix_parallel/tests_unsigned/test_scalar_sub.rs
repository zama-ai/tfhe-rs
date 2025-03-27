use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_sub_test, default_scalar_sub_test, smart_scalar_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::ServerKey;
use crate::shortint::atomic_pattern::AtomicPatternParameters;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_smart_scalar_sub);
create_parameterized_test!(integer_default_scalar_sub);
create_parameterized_test!(integer_default_overflowing_scalar_sub);

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<AtomicPatternParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_sub_parallelized);
    smart_scalar_sub_test(param, executor);
}

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<AtomicPatternParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    default_scalar_sub_test(param, executor);
}

fn integer_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<AtomicPatternParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);
    default_overflowing_scalar_sub_test(param, executor);
}
