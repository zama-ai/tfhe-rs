use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_bitwise_op::{
    signed_default_bitand_test, signed_default_bitnot_test, signed_default_bitor_test,
    signed_default_bitxor_test, signed_unchecked_bitand_test, signed_unchecked_bitor_test,
    signed_unchecked_bitxor_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_bitand);
create_gpu_parameterized_test!(integer_signed_unchecked_bitor);
create_gpu_parameterized_test!(integer_signed_unchecked_bitxor);
create_gpu_parameterized_test!(integer_signed_default_bitnot);
create_gpu_parameterized_test!(integer_signed_default_bitand);
create_gpu_parameterized_test!(integer_signed_default_bitor);
create_gpu_parameterized_test!(integer_signed_default_bitxor);

fn integer_signed_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitand);
    signed_unchecked_bitand_test(param, executor);
}

fn integer_signed_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitor);
    signed_unchecked_bitor_test(param, executor);
}

fn integer_signed_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitxor);
    signed_unchecked_bitxor_test(param, executor);
}

fn integer_signed_default_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitnot);
    signed_default_bitnot_test(param, executor);
}

fn integer_signed_default_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitand);
    signed_default_bitand_test(param, executor);
}

fn integer_signed_default_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitor);
    signed_default_bitor_test(param, executor);
}

fn integer_signed_default_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitxor);
    signed_default_bitxor_test(param, executor);
}
