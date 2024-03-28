use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_cmux::default_if_then_else_test;
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_if_then_else);

fn integer_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::if_then_else);
    default_if_then_else_test(param, executor);
}
