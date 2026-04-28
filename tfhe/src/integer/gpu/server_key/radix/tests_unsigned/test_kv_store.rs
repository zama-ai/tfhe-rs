use crate::core_crypto::gpu::CudaStreams;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::kv_store::CudaKVStore;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kv_store::{
    default_kv_store_contains_clear_value_test, default_kv_store_contains_test,
    default_kv_store_contains_value_test, default_kv_store_get_update_test,
    default_kv_store_map_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT;
use crate::integer::{IntegerKeyKind, RadixClientKey};
use crate::prelude::CastInto;
use crate::shortint::parameters::test_params::TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{TestParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128};
use std::collections::BTreeMap;

create_gpu_parameterized_test!(integer_default_kv_store_get_update);
create_gpu_parameterized_test!(integer_default_kv_store_contains_key);
create_gpu_parameterized_test!(integer_default_kv_store_contains_value);
create_gpu_parameterized_test!(integer_default_kv_store_contains_clear_value);
create_gpu_parameterized_test!(integer_default_kv_store_map);
create_gpu_parameterized_test!(kv_store_single_block_key_small_map);
create_gpu_parameterized_test!(kv_store_large_map_dispatch);

fn integer_default_kv_store_get_update(params: impl Into<TestParameters>) {
    let get_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_get);
    let update_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_update);

    default_kv_store_get_update_test(params, get_executor, update_executor);
}

fn integer_default_kv_store_contains_key(params: impl Into<TestParameters>) {
    let contains_executor = GpuFunctionExecutor::new(&CudaServerKey::kv_store_contains_key);
    default_kv_store_contains_test(params, contains_executor);
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

fn setup_gpu(params: TestParameters) -> (RadixClientKey, CudaServerKey, CudaStreams) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // Force deterministic PBS so the test is reproducible.
    sks.set_deterministic_pbs_execution(true);

    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(cks.as_ref(), &streams);
    streams.synchronize();

    (cks, cuda_sks, streams)
}

/// Cross-checks `kv_store_get` and `kv_store_contains_key` for `key` against the clear model.
fn assert_get_and_contains<Key>(
    cks: &RadixClientKey,
    cuda_sks: &CudaServerKey,
    gpu_store: &CudaKVStore<Key, CudaUnsignedRadixCiphertext>,
    clear: &BTreeMap<Key, u64>,
    key: Key,
    nb_key_blocks: usize,
    streams: &CudaStreams,
) where
    Key: DecomposableInto<u64> + CastInto<usize> + CastInto<u64> + Ord + Copy + Sync,
{
    let enc_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.as_ref()
            .encrypt_radix(CastInto::<u64>::cast_into(key), nb_key_blocks),
        streams,
    );

    let (result_ct, is_some) = cuda_sks.kv_store_get(gpu_store, &enc_key, streams);
    streams.synchronize();
    let decrypted: u64 = cks.decrypt(&result_ct.to_radix_ciphertext(streams));
    let is_some_bool = cks.decrypt_bool(&is_some.to_boolean_block(streams));

    let contains = cuda_sks.kv_store_contains_key(gpu_store, &enc_key, streams);
    streams.synchronize();
    let contains_bool = cks.decrypt_bool(&contains.to_boolean_block(streams));

    match clear.get(&key) {
        Some(&expected) => {
            assert!(is_some_bool, "get returned is_some=false for present key");
            assert_eq!(
                decrypted, expected,
                "get returned wrong value for present key"
            );
            assert!(contains_bool, "contains_key returned false for present key");
        }
        None => {
            assert!(!is_some_bool, "get returned is_some=true for absent key");
            assert_eq!(decrypted, 0, "get returned non-zero value for absent key");
            assert!(!contains_bool, "contains_key returned true for absent key");
        }
    }
}

// A 1-block key is the minimal key size: the small-map equality-selector buffer skips all
// tree-reduction allocations and uses each candidate's single comparison block directly as its
// selector, with no AND-reduction. Keys 1..message_modulus are the only non-zero values a single
// block can hold; key 0 is reserved as the absent probe.
fn kv_store_single_block_key_small_map(params: impl Into<TestParameters>) {
    let params = params.into();
    let (cks, cuda_sks, streams) = setup_gpu(params);

    let nb_key_blocks: usize = 1;
    let nb_value_blocks: usize = NB_CTXT;
    let msg_mod = cks.parameters().message_modulus().0;
    let value_modulus: u64 = msg_mod.pow(nb_value_blocks as u32);

    let mut clear: BTreeMap<u8, u64> = BTreeMap::new();
    let mut gpu_store: CudaKVStore<u8, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
    for key in 1..msg_mod {
        let key = key as u8;
        let value = (u64::from(key) * 13 + 1) % value_modulus;
        clear.insert(key, value);
        let ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.as_ref().encrypt_radix(value, nb_value_blocks),
            &streams,
        );
        gpu_store.insert(key, ct);
    }

    let present_keys: Vec<u8> = clear.keys().copied().collect();
    for key in present_keys {
        assert_get_and_contains(
            &cks,
            &cuda_sks,
            &gpu_store,
            &clear,
            key,
            nb_key_blocks,
            &streams,
        );
    }
    assert_get_and_contains(
        &cks,
        &cuda_sks,
        &gpu_store,
        &clear,
        0u8,
        nb_key_blocks,
        &streams,
    );

    let update_key: u8 = 2;
    let new_value: u64 = 7 % value_modulus;
    let enc_update_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.as_ref()
            .encrypt_radix(u64::from(update_key), nb_key_blocks),
        &streams,
    );
    let enc_new_value = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.as_ref().encrypt_radix(new_value, nb_value_blocks),
        &streams,
    );
    let is_updated =
        cuda_sks.kv_store_update(&mut gpu_store, &enc_update_key, &enc_new_value, &streams);
    streams.synchronize();
    assert!(cks.decrypt_bool(&is_updated.to_boolean_block(&streams)));
    clear.insert(update_key, new_value);

    assert_get_and_contains(
        &cks,
        &cuda_sks,
        &gpu_store,
        &clear,
        update_key,
        nb_key_blocks,
        &streams,
    );
}

// Exercises the large-map dispatch branch (more than 256 entries), unreachable with u8 keys.
// A u16 key needs 16 / log2(message_modulus) blocks. The 300-entry store takes the large-map
// path; the 20-entry store takes the small-map path.
fn kv_store_large_map_dispatch(params: impl Into<TestParameters>) {
    type LargeKey = u16;

    let params = params.into();
    let (cks, cuda_sks, streams) = setup_gpu(params);

    let msg_mod = cks.parameters().message_modulus().0;
    let nb_value_blocks: usize = NB_CTXT;
    let value_modulus: u64 = msg_mod.pow(nb_value_blocks as u32);
    let nb_key_blocks: usize = u16::BITS.div_ceil(msg_mod.ilog2()) as usize;

    for num_entries in [20_u16, 300] {
        let mut clear: BTreeMap<LargeKey, u64> = BTreeMap::new();
        let mut gpu_store: CudaKVStore<LargeKey, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        // Consecutive keys from 1 keep the test deterministic without an RNG; key 0 stays absent.
        for i in 1..=num_entries {
            let value = (u64::from(i) * 7 + 3) % value_modulus;
            clear.insert(i, value);
            let ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &cks.as_ref().encrypt_radix(value, nb_value_blocks),
                &streams,
            );
            gpu_store.insert(i, ct);
        }

        let hit_key = num_entries / 2;
        assert_get_and_contains(
            &cks,
            &cuda_sks,
            &gpu_store,
            &clear,
            hit_key,
            nb_key_blocks,
            &streams,
        );
        assert_get_and_contains(
            &cks,
            &cuda_sks,
            &gpu_store,
            &clear,
            0u16,
            nb_key_blocks,
            &streams,
        );
    }
}
