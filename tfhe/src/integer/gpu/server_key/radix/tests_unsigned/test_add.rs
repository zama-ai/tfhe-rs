use super::legacy_default_tests::{
    legacy_default_add_test, legacy_default_overflowing_add_test,
    legacy_default_sum_ciphertexts_vec_test,
};
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::bigint::U4096;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    unchecked_add_assign_test, unchecked_add_test,
};
use crate::integer::{IntegerKeyKind, RadixClientKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_unchecked_add_assign {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(multi_device_integer_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_sum_ciphertexts_vec);
create_gpu_parameterized_test!(integer_sum_ciphertexts_many_blocks {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_default_overflowing_add);
create_gpu_parameterized_test!(multi_device_integer_default_overflowing_add);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add_assign);
    unchecked_add_assign_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    legacy_default_add_test(param, executor);
}

fn multi_device_integer_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let num_gpus = get_number_of_gpus();
    if num_gpus > 1 {
        legacy_default_add_test(param, executor);
    }
}

fn integer_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &CudaServerKey,
                   ctxt: Vec<CudaUnsignedRadixCiphertext>|
     -> Option<CudaUnsignedRadixCiphertext> {
        let streams = CudaStreams::new_multi_gpu();
        sks.sum_ciphertexts(ctxt, &streams)
    };
    let executor = GpuFunctionExecutor::new(sum_vec);
    legacy_default_sum_ciphertexts_vec_test(param, executor);
}

fn integer_sum_ciphertexts_many_blocks<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);

    let clears = [1u64, 2, 3];
    for num_blocks in [512, 1024, 2048] {
        let cks = RadixClientKey::from((cks.clone(), num_blocks));
        let d_ctxts: Vec<CudaUnsignedRadixCiphertext> = clears
            .iter()
            .map(|&clear| {
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cks.encrypt(clear), &streams)
            })
            .collect();

        let d_result = sks.sum_ciphertexts(d_ctxts, &streams).unwrap();
        let result = d_result.to_radix_ciphertext(&streams);
        let decrypted: U4096 = cks.decrypt(&result);
        assert_eq!(
            decrypted,
            U4096::from(clears.iter().sum::<u64>()),
            "num_blocks = {num_blocks}"
        );
    }
}

fn integer_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    legacy_default_overflowing_add_test(param, executor);
}

fn multi_device_integer_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    let num_gpus = get_number_of_gpus();
    if num_gpus > 1 {
        legacy_default_overflowing_add_test(param, executor);
    }
}
