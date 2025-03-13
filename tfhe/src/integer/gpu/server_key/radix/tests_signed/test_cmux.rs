use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_cmux::{
    signed_default_if_then_else_test, signed_unchecked_if_then_else_test,
};
use crate::shortint::parameters::current_params::*;
use crate::shortint::parameters::current_params_gpu::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_if_then_else);
create_gpu_parameterized_test!(integer_if_then_else);

fn integer_unchecked_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_if_then_else);
    signed_unchecked_if_then_else_test(param, executor);
}

fn integer_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::if_then_else);
    signed_default_if_then_else_test(param, executor);
}
