use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_bitand_test, default_bitnot_test, default_bitor_test, default_bitxor_test,
    unchecked_bitand_test, unchecked_bitnot_test, unchecked_bitor_test, unchecked_bitxor_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_bitnot);
create_gpu_parameterized_test!(integer_unchecked_bitand);
create_gpu_parameterized_test!(integer_unchecked_bitor);
create_gpu_parameterized_test!(integer_unchecked_bitxor);
create_gpu_parameterized_test!(integer_bitnot);
create_gpu_parameterized_test!(integer_bitand);
create_gpu_parameterized_test!(integer_bitor);
create_gpu_parameterized_test!(integer_bitxor {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
});

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitnot);
    unchecked_bitnot_test(param, executor);
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitand);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitor);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitxor);
    unchecked_bitxor_test(param, executor);
}

fn integer_bitnot<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitnot);
    default_bitnot_test(param, executor);
}

fn integer_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitand);
    default_bitand_test(param, executor);
}

fn integer_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitor);
    default_bitor_test(param, executor);
}

fn integer_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitxor);
    default_bitxor_test(param, executor);
}
