use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_contains_clear_test_case, default_contains_test_case,
    default_first_index_in_clears_test_case, default_first_index_of_clear_test_case,
    default_first_index_of_test_case, default_index_in_clears_test_case,
    default_index_of_clear_test_case, default_index_of_test_case, default_is_in_clears_test_case,
    default_match_value_or_test_case, default_match_value_test_case,
    unchecked_contains_clear_test_case, unchecked_contains_test_case,
    unchecked_first_index_in_clears_test_case, unchecked_first_index_of_clear_test_case,
    unchecked_first_index_of_test_case, unchecked_index_in_clears_test_case,
    unchecked_index_of_clear_test_case, unchecked_index_of_test_case,
    unchecked_is_in_clears_test_case, unchecked_match_value_or_test_case,
    unchecked_match_value_test_case,
};

use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_match_value);
create_gpu_parameterized_test!(integer_unchecked_match_value_or);
create_gpu_parameterized_test!(integer_unchecked_contains);
create_gpu_parameterized_test!(integer_unchecked_contains_clear);
create_gpu_parameterized_test!(integer_unchecked_is_in_clears);
create_gpu_parameterized_test!(integer_unchecked_index_in_clears);
create_gpu_parameterized_test!(integer_unchecked_first_index_in_clears);
create_gpu_parameterized_test!(integer_unchecked_index_of);
create_gpu_parameterized_test!(integer_unchecked_index_of_clear);
create_gpu_parameterized_test!(integer_unchecked_first_index_of);
create_gpu_parameterized_test!(integer_unchecked_first_index_of_clear);

create_gpu_parameterized_test!(integer_default_match_value);
create_gpu_parameterized_test!(integer_default_match_value_or);
create_gpu_parameterized_test!(integer_default_contains);
create_gpu_parameterized_test!(integer_default_contains_clear);
create_gpu_parameterized_test!(integer_default_is_in_clears);
create_gpu_parameterized_test!(integer_default_index_in_clears);
create_gpu_parameterized_test!(integer_default_first_index_in_clears);
create_gpu_parameterized_test!(integer_default_index_of);
create_gpu_parameterized_test!(integer_default_index_of_clear);
create_gpu_parameterized_test!(integer_default_first_index_of);
create_gpu_parameterized_test!(integer_default_first_index_of_clear);

fn integer_unchecked_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_match_value);
    unchecked_match_value_test_case(param, executor);
}

fn integer_unchecked_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_match_value_or);
    unchecked_match_value_or_test_case(param, executor);
}

fn integer_unchecked_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_contains);
    unchecked_contains_test_case(param, executor);
}

fn integer_unchecked_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_contains_clear);
    unchecked_contains_clear_test_case(param, executor);
}

fn integer_unchecked_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_is_in_clears);
    unchecked_is_in_clears_test_case(param, executor);
}

fn integer_unchecked_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_in_clears);
    unchecked_index_in_clears_test_case(param, executor);
}

fn integer_unchecked_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_in_clears);
    unchecked_first_index_in_clears_test_case(param, executor);
}
fn integer_unchecked_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_of);
    unchecked_index_of_test_case(param, executor);
}

fn integer_unchecked_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_of_clear);
    unchecked_index_of_clear_test_case(param, executor);
}

fn integer_unchecked_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_of_clear);
    unchecked_first_index_of_clear_test_case(param, executor);
}

fn integer_unchecked_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_of);
    unchecked_first_index_of_test_case(param, executor);
}

// Default tests

fn integer_default_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::match_value);
    default_match_value_test_case(param, executor);
}

fn integer_default_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::match_value_or);
    default_match_value_or_test_case(param, executor);
}

fn integer_default_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::contains);
    default_contains_test_case(param, executor);
}

fn integer_default_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::contains_clear);
    default_contains_clear_test_case(param, executor);
}

fn integer_default_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::is_in_clears);
    default_is_in_clears_test_case(param, executor);
}

fn integer_default_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_in_clears);
    default_index_in_clears_test_case(param, executor);
}

fn integer_default_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_in_clears);
    default_first_index_in_clears_test_case(param, executor);
}

fn integer_default_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_of);
    default_index_of_test_case(param, executor);
}

fn integer_default_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_of_clear);
    default_index_of_clear_test_case(param, executor);
}

fn integer_default_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_of);
    default_first_index_of_test_case(param, executor);
}

fn integer_default_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_of_clear);
    default_first_index_of_clear_test_case(param, executor);
}
