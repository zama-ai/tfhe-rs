use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::kv_store::CudaKVStore;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kv_store::{
    default_kv_store_get_update_test, default_kv_store_map_test,
};
use crate::shortint::parameters::test_params::TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};

create_gpu_parameterized_test!(integer_default_kv_store_get_update {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_default_kv_store_get_update(params: impl Into<TestParameters>) {
    let get_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_get);
    let update_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_update);

    default_kv_store_get_update_test(params, get_executor, update_executor);
}
