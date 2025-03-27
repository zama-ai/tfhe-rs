use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_bitand_test, default_scalar_bitor_test, default_scalar_bitxor_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_scalar_bitand);
create_gpu_parameterized_test!(integer_scalar_bitor);
create_gpu_parameterized_test!(integer_scalar_bitxor);

fn integer_scalar_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    default_scalar_bitand_test(param, executor);
}

fn integer_scalar_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    default_scalar_bitor_test(param, executor);
}

fn integer_scalar_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    default_scalar_bitxor_test(param, executor);
}
