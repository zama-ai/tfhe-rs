use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_add_test, unchecked_scalar_add_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_scalar_add);
create_gpu_parametrized_test!(integer_scalar_add);

fn integer_unchecked_scalar_add<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_add);
    unchecked_scalar_add_test(param, executor);
}

fn integer_scalar_add<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_add);
    default_scalar_add_test(param, executor);
}
