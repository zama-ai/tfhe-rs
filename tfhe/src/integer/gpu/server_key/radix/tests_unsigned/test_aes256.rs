use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    aes_256_dynamic_parallelism_many_inputs_test, aes_256_fixed_parallelism_1_input_test,
    aes_256_fixed_parallelism_2_inputs_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(integer_aes_256_fixed_parallelism_1_input {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_aes_256_fixed_parallelism_2_inputs {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_aes_256_dynamic_parallelism_many_inputs {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

// The following two tests are referred to as "fixed_parallelism" because the objective is to test
// AES, in CTR mode, across all possible parallelizations of the S-box. The S-box must process 16
// bytes; the parallelization refers to the number of bytes it will process in parallel in one call:
// 1, 2, 4, 8, or 16.
//
fn integer_aes_256_fixed_parallelism_1_input<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::aes_ctr_256_with_fixed_parallelism);
    aes_256_fixed_parallelism_1_input_test(param, executor);
}

fn integer_aes_256_fixed_parallelism_2_inputs<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::aes_ctr_256_with_fixed_parallelism);
    aes_256_fixed_parallelism_2_inputs_test(param, executor);
}

// The test referred to as "dynamic_parallelism" will seek the maximum s-box parallelization that
// the machine can support.
//
fn integer_aes_256_dynamic_parallelism_many_inputs<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::aes_ctr_256);
    aes_256_dynamic_parallelism_many_inputs_test(param, executor);
}
