use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_abs::{
    signed_default_absolute_value_test, signed_unchecked_absolute_value_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_abs);
create_gpu_parameterized_test!(integer_signed_abs);

fn integer_signed_unchecked_abs<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_abs);
    signed_unchecked_absolute_value_test(param, executor);
}

fn integer_signed_abs<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::abs);
    signed_default_absolute_value_test(param, executor);
}
