use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_default_block_mul_test, default_mul_test, default_overflowing_mul_test,
    smart_block_mul_test, smart_mul_test, unchecked_block_mul_test,
    unchecked_mul_corner_cases_test, unchecked_mul_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_unchecked_mul_corner_cases);
create_parametrized_test!(integer_unchecked_block_mul);
create_parametrized_test!(integer_smart_block_mul);
create_parametrized_test!(integer_default_block_mul);
create_parametrized_test!(integer_smart_mul);
create_parametrized_test!(integer_default_mul);
create_parametrized_test!(integer_default_unsigned_overflowing_mul);
create_parametrized_test!(integer_unchecked_mul);

fn integer_unchecked_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul_parallelized);
    unchecked_mul_test(param, executor);
}

fn integer_unchecked_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_block_mul_parallelized);
    unchecked_block_mul_test(param, executor);
}

fn integer_unchecked_mul_corner_cases<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul_parallelized);
    unchecked_mul_corner_cases_test(param, executor);
}

fn integer_smart_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_mul_parallelized);
    smart_mul_test(param, executor);
}

fn integer_smart_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_block_mul_parallelized);
    smart_block_mul_test(param, executor);
}

fn integer_default_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    default_mul_test(param, executor);
}

fn integer_default_unsigned_overflowing_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_mul_parallelized);
    default_overflowing_mul_test(param, executor);
}

fn integer_default_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::block_mul_parallelized);
    default_default_block_mul_test(param, executor);
}
