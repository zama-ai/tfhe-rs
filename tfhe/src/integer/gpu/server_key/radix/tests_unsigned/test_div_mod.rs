use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_div_mod::{
    default_div_rem_test, default_div_test, default_rem_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_div);
create_gpu_parametrized_test!(integer_div_rem);
create_gpu_parametrized_test!(integer_rem);

fn integer_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::div);
    default_div_test(param, executor);
}

fn integer_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::div_rem);
    default_div_rem_test(param, executor);
}

fn integer_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rem);
    default_rem_test(param, executor);
}
