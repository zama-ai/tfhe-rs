use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_add::{
    signed_default_add_test, signed_unchecked_add_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_add);
create_gpu_parametrized_test!(integer_add);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    signed_unchecked_add_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    signed_default_add_test(param, executor);
}
