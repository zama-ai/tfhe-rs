use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_bitand_test, default_bitnot_test, default_bitor_test, default_bitxor_test,
    unchecked_bitand_test, unchecked_bitnot_test, unchecked_bitor_test, unchecked_bitxor_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_bitnot);
create_gpu_parametrized_test!(integer_unchecked_bitand);
create_gpu_parametrized_test!(integer_unchecked_bitor);
create_gpu_parametrized_test!(integer_unchecked_bitxor);
create_gpu_parametrized_test!(integer_bitnot);
create_gpu_parametrized_test!(integer_bitand);
create_gpu_parametrized_test!(integer_bitor);
create_gpu_parametrized_test!(integer_bitxor);

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitnot);
    unchecked_bitnot_test(param, executor);
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitand);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitor);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitxor);
    unchecked_bitxor_test(param, executor);
}

fn integer_bitnot<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitnot);
    default_bitnot_test(param, executor);
}

fn integer_bitand<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitand);
    default_bitand_test(param, executor);
}

fn integer_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitor);
    default_bitor_test(param, executor);
}

fn integer_bitxor<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitxor);
    default_bitxor_test(param, executor);
}
