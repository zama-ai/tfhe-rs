use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::kv_store::CudaKVStore;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kv_store::{
    default_kv_store_contains_clear_value_test, default_kv_store_contains_test,
    default_kv_store_contains_value_test, default_kv_store_get_update_test,
    default_kv_store_map_test, GET_UPDATE_STORE_SIZES,
};
use crate::shortint::parameters::test_params::TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};

create_gpu_parameterized_test!(integer_default_kv_store_get_update);
create_gpu_parameterized_test!(integer_default_kv_store_contains_key);
create_gpu_parameterized_test!(integer_default_kv_store_contains_value);
create_gpu_parameterized_test!(integer_default_kv_store_contains_clear_value);
create_gpu_parameterized_test!(integer_default_kv_store_map);
create_gpu_parameterized_test!(integer_kv_store_large_map_get_update);
create_gpu_parameterized_test!(integer_kv_store_large_map_contains_key);
create_gpu_parameterized_test!(integer_kv_store_single_block_key_get_update);
create_gpu_parameterized_test!(integer_kv_store_single_block_key_contains_key);

fn integer_default_kv_store_get_update(params: impl Into<TestParameters>) {
    let get_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_get);
    let update_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_update);

    default_kv_store_get_update_test::<u8, _, _, _>(
        params,
        get_executor,
        update_executor,
        None,
        GET_UPDATE_STORE_SIZES,
        usize::MAX,
    );
}

fn integer_default_kv_store_contains_key(params: impl Into<TestParameters>) {
    let contains_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_key);
    default_kv_store_contains_test::<u8, _, _>(params, contains_executor, None, &[20], usize::MAX);
}

fn integer_default_kv_store_contains_value(params: impl Into<TestParameters>) {
    let contains_value_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_value);
    default_kv_store_contains_value_test(params, contains_value_executor);
}

fn integer_default_kv_store_contains_clear_value(params: impl Into<TestParameters>) {
    let contains_clear_value_executor =
        GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_clear_value);
    default_kv_store_contains_clear_value_test(params, contains_clear_value_executor);
}

fn integer_default_kv_store_map(params: impl Into<TestParameters>) {
    // `kv_store_map` is generic over the mapping closure, so it cannot be passed as a bare
    // function item; wrap it so the executor binds a concrete `Fn`.
    let closure =
        |sks: &CudaServerKey,
         store: &mut CudaKVStore<u8, CudaUnsignedRadixCiphertext>,
         encrypted_key: &CudaUnsignedRadixCiphertext,
         func: &dyn Fn(CudaUnsignedRadixCiphertext) -> CudaUnsignedRadixCiphertext,
         streams: &CudaStreams| { sks.kv_store_map(store, encrypted_key, func, streams) };
    let map_executor = GpuFunctionExecutor::new(closure);
    default_kv_store_map_test(params, map_executor);
}

// 300 entries exceeds the CUDA backend's small-map limit
// (KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES = 256), forcing the large-map
// equality-selector path; 20 entries stays on the small-map path for contrast. u16 keys are
// required because a u8 key space caps the store at 256 entries. Probes are capped at 2 so
// the 300-entry case stays fast.
fn integer_kv_store_large_map_get_update(params: impl Into<TestParameters>) {
    let get_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_get);
    let update_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_update);

    default_kv_store_get_update_test::<u16, _, _, _>(
        params,
        get_executor,
        update_executor,
        None,
        &[20, 300],
        2,
    );
}

fn integer_kv_store_large_map_contains_key(params: impl Into<TestParameters>) {
    let contains_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_key);
    default_kv_store_contains_test::<u16, _, _>(params, contains_executor, None, &[20, 300], 2);
}

// A 1-block key is the minimal key width: the small-map equality-selector buffer skips all
// tree-reduction allocations and uses each candidate's single comparison block directly as its
// selector, with no AND-reduction. With message_modulus = 4 the key space is {0..3}, so a
// 3-entry store leaves one key free for absent-key probes.
fn integer_kv_store_single_block_key_get_update(params: impl Into<TestParameters>) {
    let get_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_get);
    let update_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_update);

    default_kv_store_get_update_test::<u8, _, _, _>(
        params,
        get_executor,
        update_executor,
        Some(1),
        &[3],
        usize::MAX,
    );
}

fn integer_kv_store_single_block_key_contains_key(params: impl Into<TestParameters>) {
    let contains_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_key);
    default_kv_store_contains_test::<u8, _, _>(
        params,
        contains_executor,
        Some(1),
        &[3],
        usize::MAX,
    );
}
