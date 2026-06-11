use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kv_store::default_kv_store_get_update_test;
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

// Tests the large-map dispatch path (num_entries > KV_STORE_EQ_SELECTORS_SMALL_MAP_MAX_ENTRIES =
// 256) which routes through host_compute_eq_selectors_ct_vs_clears (sequential accumulator).
//
// KeyType = u8 allows at most 256 entries, so it cannot reach the large-map branch.
// This test uses u16 keys, building a store with 300 entries (large-map path) and one with
// 20 entries (small-map path), then verifies get and contains_key agree with a clear model.
// Both regimes share the same verification logic so a regression in either dispatch branch
// surfaces as an assertion failure.
#[test]
fn test_gpu_kv_store_large_map_dispatch_param_message_2_carry_2_ks_pbs_tuniform_2m128() {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::server_key::radix::kv_store::CudaKVStore;
    use crate::integer::{gen_keys, IntegerKeyKind};
    use crate::shortint::ShortintParameterSet;
    use std::collections::BTreeMap;

    // u16 key: num_key_blocks = 16 / log2(message_modulus). With 2-bit message modulus that
    // is 8 blocks per key, well within what the GPU supports.
    type LargeKey = u16;

    let params: ShortintParameterSet = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
    let (cks, _sks) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);
    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(&cks, &streams);

    let msg_mod = cks.parameters().message_modulus().0;
    // Value space: use the same 4-block radix as the CPU tests (NB_CTXT = 4).
    let nb_value_blocks: usize = 4;
    let value_modulus: u64 = msg_mod.pow(nb_value_blocks as u32);
    // Key blocks: 16-bit key over 2-bit message modulus = 8 blocks.
    let nb_key_blocks: usize = u16::BITS.div_ceil(msg_mod.ilog2()) as usize;

    // Verify get and contains_key for `num_entries`-entry stores against a clear model.
    // Checks one hit (key that exists) and one miss (key 0, which is never inserted).
    // Keys 1..=num_entries are inserted; key 0 is always absent.
    for num_entries in [20_usize, 300] {
        let mut clear: BTreeMap<LargeKey, u64> = BTreeMap::new();
        let mut gpu_store: CudaKVStore<LargeKey, CudaUnsignedRadixCiphertext> = CudaKVStore::new();
        // Generate consecutive keys starting from 1 to guarantee uniqueness and keep the
        // test deterministic without requiring a keycache or RNG.
        for i in 1..=(num_entries as u16) {
            let value = (i as u64 * 7 + 3) % value_modulus;
            clear.insert(i, value);
            let ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &cks.encrypt_radix(value, nb_value_blocks),
                &streams,
            );
            gpu_store.insert(i, ct);
        }

        // Hit: key = num_entries / 2, guaranteed present.
        let hit_key = (num_entries / 2) as u16;
        let expected_value = *clear.get(&hit_key).unwrap();
        let enc_hit_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt_radix(hit_key as u64, nb_key_blocks),
            &streams,
        );

        let (result_ct, is_some) = cuda_sks.kv_store_get(&gpu_store, &enc_hit_key, &streams);
        streams.synchronize();
        let decrypted: u64 = cks.decrypt_radix(&result_ct.to_radix_ciphertext(&streams));
        let is_some_bool = cks.decrypt_bool(&is_some.to_boolean_block(&streams));
        assert!(
            is_some_bool,
            "num_entries={num_entries}: kv_store_get hit returned is_some=false"
        );
        assert_eq!(
            decrypted, expected_value,
            "num_entries={num_entries}: kv_store_get hit returned wrong value"
        );

        let contains = cuda_sks.kv_store_contains_key(&gpu_store, &enc_hit_key, &streams);
        streams.synchronize();
        let contains_bool = cks.decrypt_bool(&contains.to_boolean_block(&streams));
        assert!(
            contains_bool,
            "num_entries={num_entries}: kv_store_contains_key returned false for present key"
        );

        // Miss: key 0 is never inserted.
        let miss_key: u16 = 0;
        let enc_miss_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt_radix(miss_key as u64, nb_key_blocks),
            &streams,
        );

        let (_, is_some_miss) = cuda_sks.kv_store_get(&gpu_store, &enc_miss_key, &streams);
        streams.synchronize();
        let is_some_miss_bool = cks.decrypt_bool(&is_some_miss.to_boolean_block(&streams));
        assert!(
            !is_some_miss_bool,
            "num_entries={num_entries}: kv_store_get miss returned is_some=true"
        );

        let contains_miss = cuda_sks.kv_store_contains_key(&gpu_store, &enc_miss_key, &streams);
        streams.synchronize();
        let contains_miss_bool = cks.decrypt_bool(&contains_miss.to_boolean_block(&streams));
        assert!(
            !contains_miss_bool,
            "num_entries={num_entries}: kv_store_contains_key returned true for absent key"
        );
    }
}
