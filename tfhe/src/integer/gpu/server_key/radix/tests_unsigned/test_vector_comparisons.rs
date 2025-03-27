use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

use crate::integer::server_key::radix_parallel::tests_unsigned::test_vector_comparisons::{
    default_all_eq_slices_test_case, unchecked_all_eq_slices_test_case,
    unchecked_slice_contains_test_case,
};

create_gpu_parameterized_test!(integer_unchecked_all_eq_slices_test_case);
create_gpu_parameterized_test!(integer_default_all_eq_slices_test_case);
create_gpu_parameterized_test!(integer_unchecked_contains_slice_test_case);

fn integer_unchecked_all_eq_slices_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_all_eq_slices);
    unchecked_all_eq_slices_test_case(param, executor);
}

fn integer_default_all_eq_slices_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::all_eq_slices);
    default_all_eq_slices_test_case(param, executor);
}

fn integer_unchecked_contains_slice_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_contains_sub_slice);
    unchecked_slice_contains_test_case(param, executor);
}
