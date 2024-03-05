use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_neg_test, unchecked_neg_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_neg);
create_gpu_parametrized_test!(integer_neg);

fn integer_unchecked_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_neg);
    unchecked_neg_test(param, executor);
}

fn integer_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::neg);
    default_neg_test(param, executor);
}
