use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_bitand_test, default_bitnot_test, default_bitor_test, default_bitxor_test,
    smart_bitand_test, smart_bitor_test, smart_bitxor_test, unchecked_bitand_test,
    unchecked_bitnot_test, unchecked_bitor_test, unchecked_bitxor_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_smart_bitand);
create_parameterized_test!(integer_smart_bitor);
create_parameterized_test!(integer_smart_bitxor);
create_parameterized_test!(integer_default_bitand);
create_parameterized_test!(integer_default_bitor);
create_parameterized_test!(integer_default_bitnot);
create_parameterized_test!(integer_default_bitxor);
create_parameterized_test!(integer_unchecked_bitand);
create_parameterized_test!(integer_unchecked_bitor);
create_parameterized_test!(integer_unchecked_bitnot);
create_parameterized_test!(integer_unchecked_bitxor);

fn integer_smart_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitand_parallelized);
    smart_bitand_test(param, executor);
}

fn integer_smart_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitor_parallelized);
    smart_bitor_test(param, executor);
}

fn integer_smart_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitxor_parallelized);
    smart_bitxor_test(param, executor);
}

fn integer_default_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    default_bitand_test(param, executor);
}

fn integer_default_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    default_bitor_test(param, executor);
}

fn integer_default_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    default_bitxor_test(param, executor);
}

fn integer_default_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    default_bitnot_test(param, executor);
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor_parallelized);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor_parallelized);
    unchecked_bitxor_test(param, executor);
}

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    unchecked_bitnot_test(param, executor);
}
