use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_sub_test, unchecked_scalar_sub_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_scalar_sub);
create_gpu_parameterized_test!(integer_scalar_sub);

fn integer_unchecked_scalar_sub<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_sub);
    unchecked_scalar_sub_test(param, executor);
}

fn integer_scalar_sub<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_sub);
    default_scalar_sub_test(param, executor);
}
