use super::legacy_default_tests::{legacy_default_neg_test, legacy_default_overflowing_neg_test};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_neg::unchecked_neg_test;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_neg);
create_gpu_parameterized_test!(integer_neg);
create_gpu_parameterized_test!(integer_overflowing_neg);

fn integer_unchecked_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_neg);
    unchecked_neg_test(param, executor);
}

fn integer_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::neg);
    legacy_default_neg_test(param, executor);
}

fn integer_overflowing_neg(param: impl Into<TestParameters>) {
    let executor = GpuFunctionExecutor::new(&CudaServerKey::overflowing_neg);
    legacy_default_overflowing_neg_test(param, executor);
}
