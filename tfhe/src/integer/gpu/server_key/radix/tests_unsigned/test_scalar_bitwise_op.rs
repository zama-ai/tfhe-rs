use super::legacy_default_tests::{
    legacy_default_scalar_bitand_test, legacy_default_scalar_bitor_test,
    legacy_default_scalar_bitxor_test,
};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_default_scalar_bitand);
create_gpu_parameterized_test!(integer_default_scalar_bitor);
create_gpu_parameterized_test!(integer_default_scalar_bitxor);

fn integer_default_scalar_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    legacy_default_scalar_bitand_test(param, executor);
}

fn integer_default_scalar_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    legacy_default_scalar_bitor_test(param, executor);
}

fn integer_default_scalar_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    legacy_default_scalar_bitxor_test(param, executor);
}
