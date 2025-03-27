use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_add::{
    signed_default_overflowing_scalar_add_test, signed_default_scalar_add_test,
    signed_unchecked_scalar_add_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_scalar_add);
create_gpu_parameterized_test!(integer_signed_scalar_add);
create_gpu_parameterized_test!(integer_signed_overflowing_scalar_add);

fn integer_signed_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_add);
    signed_unchecked_scalar_add_test(param, executor);
}

fn integer_signed_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_add);
    signed_default_scalar_add_test(param, executor);
}

fn integer_signed_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::signed_overflowing_scalar_add);
    signed_default_overflowing_scalar_add_test(param, executor);
}
