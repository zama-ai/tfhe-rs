use crate::core_crypto::prelude::{CastFrom, UnsignedNumeric};
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NB_CTXT};
use crate::integer::server_key::KVStore;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::{TestParameters, *};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::Arc;

create_parameterized_test!(
    integer_default_kv_store_get_update
    {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(
    integer_default_kv_store_contains_key
    {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(
    integer_default_kv_store_contains_value
    {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(
    integer_default_kv_store_contains_clear_value
    {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(
    integer_default_kv_store_map
    {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);

fn integer_default_kv_store_get_update(params: impl Into<TestParameters>) {
    let get_executor = CpuFunctionExecutor::new(&ServerKey::kv_store_get);
    let update_executor = CpuFunctionExecutor::new(&ServerKey::kv_store_update);
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
    let contains_executor = CpuFunctionExecutor::new(&ServerKey::kv_store_contains_key);
    default_kv_store_contains_test::<u8, _, _>(params, contains_executor, None, &[20], usize::MAX);
}

fn integer_default_kv_store_contains_value(params: impl Into<TestParameters>) {
    let contains_value_executor = CpuFunctionExecutor::new(&ServerKey::kv_store_contains_value);
    default_kv_store_contains_value_test::<u8, _, _>(params, contains_value_executor);
}

fn integer_default_kv_store_contains_clear_value(params: impl Into<TestParameters>) {
    let contains_clear_value_executor =
        CpuFunctionExecutor::new(&ServerKey::kv_store_contains_clear_value);
    default_kv_store_contains_clear_value_test::<u8, _, _>(params, contains_clear_value_executor);
}

fn integer_default_kv_store_map(params: impl Into<TestParameters>) {
    let closure = |sks: &ServerKey,
                   store: &mut KVStore<u8, RadixCiphertext>,
                   encrypted_key: &RadixCiphertext,
                   func: &dyn Fn(RadixCiphertext) -> RadixCiphertext| {
        sks.kv_store_map(store, encrypted_key, func)
    };
    let map_executor = CpuFunctionExecutor::new(closure);
    default_kv_store_map_test::<u8, _, _>(params, map_executor);
}

fn get_num_block_for_key<Key: UnsignedNumeric>(msg_mod: MessageModulus) -> usize {
    Key::BITS.div_ceil(msg_mod.0.ilog2() as usize)
}

// Store sizes covering distinct paths in the GPU fold-sum schedule (a GPU implementation
// detail; the CPU runs the same sizes for parity):
//
//   3  — below the noise budget: a fold-only schedule with no PBS round.
//  20  — remainder is an exact multiple of the per-round budget: folds, absorbs the
//        tail, and finishes after a second fold-only round.
//  26  — remainder is not a multiple of the budget at any full round: takes the
//        most general schedule, with several PBS rounds.
pub const GET_UPDATE_STORE_SIZES: &[usize] = &[3, 20, 26];

/// Number of distinct keys representable: bounded both by the encrypted key width and by the
/// clear key type's range.
fn key_space_modulus<Key: UnsignedNumeric>(msg_mod: MessageModulus, nb_key_blocks: usize) -> u128 {
    assert!(Key::BITS < 128);
    (msg_mod.0 as u128)
        .pow(nb_key_blocks as u32)
        .min(1u128 << Key::BITS)
}

fn random_key<Key: CastFrom<u64>>(key_modulus: u128) -> Key {
    Key::cast_from((rand::random::<u128>() % key_modulus) as u64)
}

pub fn default_kv_store_get_update_test<Key, P, T1, T2>(
    params: P,
    mut kv_store_get: T1,
    mut kv_store_update: T2,
    nb_key_blocks: Option<usize>,
    store_sizes: &[usize],
    max_probes: usize,
) where
    Key: DecomposableInto<u64> + UnsignedNumeric + CastFrom<u64> + Ord + Copy + Display,
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a KVStore<Key, RadixCiphertext>, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
    T2: for<'a> FunctionExecutor<
        (
            &'a mut KVStore<Key, RadixCiphertext>,
            &'a RadixCiphertext,
            &'a RadixCiphertext,
        ),
        BooleanBlock,
    >,
{
    let params = params.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let nb_blocks_key =
        nb_key_blocks.unwrap_or_else(|| get_num_block_for_key::<Key>(params.message_modulus()));
    let key_modulus = key_space_modulus::<Key>(params.message_modulus(), nb_blocks_key);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_get.setup(&cks, sks.clone());
    kv_store_update.setup(&cks, sks);

    // Test on an empty store
    {
        let mut empty_map: KVStore<Key, RadixCiphertext> = KVStore::new();
        let key = random_key::<Key>(key_modulus);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

        let (result, is_some) = kv_store_get.execute((&empty_map, &encrypted_key));
        assert!(!cks.decrypt_bool(&is_some));
        assert_eq!(cks.decrypt::<u64>(&result), 0);

        let new_value = rand::random::<u64>() % modulus;
        let encrypted_new_value: RadixCiphertext = cks.encrypt(new_value);
        let is_some =
            kv_store_update.execute((&mut empty_map, &encrypted_key, &encrypted_new_value));
        assert!(!cks.decrypt_bool(&is_some));
    }

    for &num_keys in store_sizes {
        let (mut map, mut clear_store) =
            create_filled_stores::<Key>(num_keys, key_modulus, modulus, &cks);
        let num_probes = num_keys.div_ceil(2).min(max_probes);

        // Test a key that does not exist.
        for _ in 0..num_probes {
            let key = generate_unused_key(&clear_store, key_modulus);
            let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

            let (result, is_some) = kv_store_get.execute((&map, &encrypted_key));
            assert!(!cks.decrypt_bool(&is_some));
            assert_eq!(cks.decrypt::<u64>(&result), 0);

            let new_value = rand::random::<u64>() % modulus;
            let encrypted_new_value: RadixCiphertext = cks.encrypt(new_value);
            let is_some = kv_store_update.execute((&mut map, &encrypted_key, &encrypted_new_value));
            assert!(!cks.decrypt_bool(&is_some));

            panic_if_not_the_same(&map, &clear_store, &cks);
        }

        // Test a key that exists.
        for _ in 0..num_probes {
            let key_index = rand::random::<usize>() % num_keys;
            let key_target = *clear_store.iter().nth(key_index).unwrap().0;
            let encrypted_key = cks.as_ref().encrypt_radix(key_target, nb_blocks_key);

            let expected_value = clear_store.get(&key_target).unwrap();

            let (result, is_some) = kv_store_get.execute((&map, &encrypted_key));
            assert!(cks.decrypt_bool(&is_some));
            assert_eq!(cks.decrypt::<u64>(&result), *expected_value);

            let new_value = rand::random::<u64>() % modulus;
            let encrypted_new_value: RadixCiphertext = cks.encrypt(new_value);
            let is_some = kv_store_update.execute((&mut map, &encrypted_key, &encrypted_new_value));
            assert!(cks.decrypt_bool(&is_some));

            clear_store.insert(key_target, new_value);

            panic_if_not_properly_updated(&map, &clear_store, key_target, &cks);
        }
    }
}

pub fn default_kv_store_map_test<Key, P, T>(params: P, mut kv_store_map: T)
where
    Key: DecomposableInto<u64> + UnsignedNumeric + CastFrom<u64> + Ord + Copy + Display,
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a mut KVStore<Key, RadixCiphertext>,
            &'a RadixCiphertext,
            &'a dyn Fn(RadixCiphertext) -> RadixCiphertext,
        ),
        (RadixCiphertext, RadixCiphertext, BooleanBlock),
    >,
{
    let params = params.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let nb_blocks_key = get_num_block_for_key::<Key>(params.message_modulus());

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_map.setup(&cks, sks);

    let key_modulus = key_space_modulus::<Key>(params.message_modulus(), nb_blocks_key);

    // Test on an empty store
    {
        let mut empty_map: KVStore<Key, RadixCiphertext> = KVStore::new();
        let key = random_key::<Key>(key_modulus);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);
        let identity: &dyn Fn(RadixCiphertext) -> RadixCiphertext = &|x| x;
        let (_, _, is_some) = kv_store_map.execute((&mut empty_map, &encrypted_key, identity));
        assert!(!cks.decrypt_bool(&is_some));
    }

    let num_keys = 20usize;
    let (mut map, mut clear_store) = create_filled_stores(num_keys, key_modulus, modulus, &cks);

    let clear_function = |x: u64| -> u64 { x / 3 };
    let function = Box::new(|input: RadixCiphertext| -> RadixCiphertext {
        // Compute in the clear domain so that it is faster
        let value = cks.decrypt::<u64>(&input);
        let result = clear_function(value);
        cks.encrypt(result)
    });

    // Test modifying a key that does not exist
    for _ in 0..num_keys.div_ceil(2) {
        let key = generate_unused_key(&clear_store, key_modulus);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

        let (_, _, is_some) = kv_store_map.execute((&mut map, &encrypted_key, &function));
        assert!(!cks.decrypt_bool(&is_some));

        panic_if_not_the_same(&map, &clear_store, &cks);
    }

    // Test modifying a key that exists
    for _ in 0..num_keys.div_ceil(2) {
        let key_index = rand::random::<usize>() % num_keys;
        let key_target = *clear_store.iter().nth(key_index).unwrap().0;
        let encrypted_key = cks.as_ref().encrypt_radix(key_target, nb_blocks_key);

        let (old_value, new_value) = clear_store
            .get(&key_target)
            .copied()
            .map(|old_value| (old_value, clear_function(old_value)))
            .unwrap();

        let (e_old_value, e_new_value, is_some) = kv_store_map.execute((
            &mut map,
            &encrypted_key,
            &function as &dyn Fn(RadixCiphertext) -> RadixCiphertext,
        ));
        assert!(cks.decrypt_bool(&is_some));
        assert_eq!(cks.decrypt::<u64>(&e_new_value), new_value);
        assert_eq!(cks.decrypt::<u64>(&e_old_value), old_value);

        clear_store.insert(key_target, new_value);

        panic_if_not_properly_updated(&map, &clear_store, key_target, &cks);
    }
}

/// Creates a pair of stores (encrypted and clear) filled with random key-value pairs.
///
/// # Arguments
/// * `num_keys` - Number of key-value pairs to generate
/// * `key_modulus` - Size of the key space keys are drawn from
/// * `modulus` - Maximum value for the random values
/// * `cks` - Client key for encryption
///
/// # Returns
/// A tuple containing the encrypted store and its clear counterpart
fn create_filled_stores<Key>(
    num_keys: usize,
    key_modulus: u128,
    modulus: u64,
    cks: &RadixClientKey,
) -> (KVStore<Key, RadixCiphertext>, BTreeMap<Key, u64>)
where
    Key: CastFrom<u64> + Ord + Copy,
{
    // The absent-key probes need at least one unused key in the key space.
    assert!(
        (num_keys as u128) < key_modulus,
        "store size {num_keys} must be smaller than the key space {key_modulus}"
    );
    let mut store = KVStore::new();
    let mut clear_store = BTreeMap::<Key, u64>::new();
    while clear_store.len() != num_keys {
        let (key, value) = (
            random_key::<Key>(key_modulus),
            rand::random::<u64>() % modulus,
        );
        clear_store.insert(key, value);

        let encrypted_value = cks.encrypt(value);
        store.insert(key, encrypted_value);
    }
    assert_eq!(store.len(), clear_store.len());

    (store, clear_store)
}

/// Panics if any of the key-value pairs of the encrypted store
/// is not the same as the clear store.
fn panic_if_not_the_same<Key>(
    map: &KVStore<Key, RadixCiphertext>,
    clear_store: &BTreeMap<Key, u64>,
    cks: &RadixClientKey,
) where
    Key: Ord + Copy + Display,
{
    assert_eq!(
        map.len(),
        clear_store.len(),
        "Stores do not have the same number of keys"
    );

    for (key, stored_value) in map.iter() {
        let original_value = clear_store.get(key).unwrap();
        let decrypted_value: u64 = cks.decrypt(stored_value);
        assert_eq!(
            decrypted_value, *original_value,
            "Value is not the same for key={key}\
             expected={original_value}, stored={decrypted_value}"
        );
    }
}

pub fn default_kv_store_contains_test<Key, P, T1>(
    params: P,
    mut kv_store_contains_key: T1,
    nb_key_blocks: Option<usize>,
    store_sizes: &[usize],
    max_probes: usize,
) where
    Key: DecomposableInto<u64> + UnsignedNumeric + CastFrom<u64> + Ord + Copy + Display,
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a KVStore<Key, RadixCiphertext>, &'a RadixCiphertext),
        BooleanBlock,
    >,
{
    let params = params.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let nb_blocks_key =
        nb_key_blocks.unwrap_or_else(|| get_num_block_for_key::<Key>(params.message_modulus()));
    let key_modulus = key_space_modulus::<Key>(params.message_modulus(), nb_blocks_key);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_contains_key.setup(&cks, sks);

    // Test on an empty store
    {
        let empty_map: KVStore<Key, RadixCiphertext> = KVStore::new();
        let key = random_key::<Key>(key_modulus);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);
        let is_contained = kv_store_contains_key.execute((&empty_map, &encrypted_key));
        assert!(!cks.decrypt_bool(&is_contained));
    }

    for &num_keys in store_sizes {
        let (map, clear_store) = create_filled_stores::<Key>(num_keys, key_modulus, modulus, &cks);
        let num_probes = num_keys.div_ceil(2).min(max_probes);

        // Test a key that does not exist
        for _ in 0..num_probes {
            let key = generate_unused_key(&clear_store, key_modulus);
            let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

            let is_contained = kv_store_contains_key.execute((&map, &encrypted_key));
            assert!(!cks.decrypt_bool(&is_contained));
        }

        // Test a key that exists
        for _ in 0..num_probes {
            let key_index = rand::random::<usize>() % num_keys;
            let key_target = *clear_store.iter().nth(key_index).unwrap().0;
            let encrypted_key = cks.as_ref().encrypt_radix(key_target, nb_blocks_key);

            let is_contained = kv_store_contains_key.execute((&map, &encrypted_key));
            assert!(cks.decrypt_bool(&is_contained));
        }
    }
}

pub fn default_kv_store_contains_value_test<Key, P, T1>(params: P, mut kv_store_contains_value: T1)
where
    Key: DecomposableInto<u64> + UnsignedNumeric + CastFrom<u64> + Ord + Copy + Display,
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a KVStore<Key, RadixCiphertext>, &'a RadixCiphertext),
        BooleanBlock,
    >,
{
    let params = params.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let nb_blocks_key = get_num_block_for_key::<Key>(params.message_modulus());
    let key_modulus = key_space_modulus::<Key>(params.message_modulus(), nb_blocks_key);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_contains_value.setup(&cks, sks);

    // Test on an empty store
    {
        let empty_map: KVStore<Key, RadixCiphertext> = KVStore::new();
        let value: RadixCiphertext = cks.encrypt(rand::random::<u64>() % modulus);
        let is_contained = kv_store_contains_value.execute((&empty_map, &value));
        assert!(!cks.decrypt_bool(&is_contained));
    }

    let num_keys = 20usize;
    let (map, clear_store) = create_filled_stores(num_keys, key_modulus, modulus, &cks);

    // Test a value that exists in the store
    for _ in 0..num_keys.div_ceil(2) {
        let value_index = rand::random::<usize>() % num_keys;
        let target_value = *clear_store.values().nth(value_index).unwrap();
        let encrypted_value: RadixCiphertext = cks.encrypt(target_value);

        let is_contained = kv_store_contains_value.execute((&map, &encrypted_value));
        assert!(cks.decrypt_bool(&is_contained));
    }

    // Test a value that does not exist in the store
    for _ in 0..num_keys.div_ceil(2) {
        let value = loop {
            let candidate = rand::random::<u64>() % modulus;
            if !clear_store.values().any(|&v| v == candidate) {
                break candidate;
            }
        };
        let encrypted_value: RadixCiphertext = cks.encrypt(value);

        let is_contained = kv_store_contains_value.execute((&map, &encrypted_value));
        assert!(!cks.decrypt_bool(&is_contained));
    }
}

pub fn default_kv_store_contains_clear_value_test<Key, P, T1>(
    params: P,
    mut kv_store_contains_clear_value: T1,
) where
    Key: DecomposableInto<u64> + UnsignedNumeric + CastFrom<u64> + Ord + Copy + Display,
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<(&'a KVStore<Key, RadixCiphertext>, u64), BooleanBlock>,
{
    let params = params.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let nb_blocks_key = get_num_block_for_key::<Key>(params.message_modulus());
    let key_modulus = key_space_modulus::<Key>(params.message_modulus(), nb_blocks_key);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_contains_clear_value.setup(&cks, sks);

    // Test on an empty store
    {
        let empty_map: KVStore<Key, RadixCiphertext> = KVStore::new();
        let is_contained =
            kv_store_contains_clear_value.execute((&empty_map, rand::random::<u64>() % modulus));
        assert!(!cks.decrypt_bool(&is_contained));
    }

    let num_keys = 20usize;
    let (map, clear_store) = create_filled_stores(num_keys, key_modulus, modulus, &cks);

    // Test a value that exists in the store
    for _ in 0..num_keys.div_ceil(2) {
        let value_index = rand::random::<usize>() % num_keys;
        let target_value = *clear_store.values().nth(value_index).unwrap();

        let is_contained = kv_store_contains_clear_value.execute((&map, target_value));
        assert!(cks.decrypt_bool(&is_contained));
    }

    // Test a value that does not exist in the store
    for _ in 0..num_keys.div_ceil(2) {
        let value = loop {
            let candidate = rand::random::<u64>() % modulus;
            if !clear_store.values().any(|&v| v == candidate) {
                break candidate;
            }
        };

        let is_contained = kv_store_contains_clear_value.execute((&map, value));
        assert!(!cks.decrypt_bool(&is_contained));
    }
}

fn generate_unused_key<Key>(clear_store: &BTreeMap<Key, u64>, key_modulus: u128) -> Key
where
    Key: CastFrom<u64> + Ord,
{
    loop {
        let key = random_key::<Key>(key_modulus);
        if !clear_store.contains_key(&key) {
            return key;
        }
    }
}

/// Panics if any of the key-value pairs of the encrypted store
/// is not the same as the clear store.
///
/// To be used after updating a key.
/// `update_key`, tells which key was last updated
/// so that the panic message is clearer
fn panic_if_not_properly_updated<Key>(
    map: &KVStore<Key, RadixCiphertext>,
    clear_store: &BTreeMap<Key, u64>,
    updated_key: Key,
    cks: &RadixClientKey,
) where
    Key: Ord + Copy + Display,
{
    assert_eq!(
        map.len(),
        clear_store.len(),
        "Stores do not have the same number of keys"
    );

    for (key, stored_value) in map.iter() {
        let expected_value = clear_store.get(key).unwrap();
        let decrypted_value: u64 = cks.decrypt(stored_value);

        if decrypted_value != *expected_value {
            if key == &updated_key {
                panic!(
                    "Value for key={key} was not properly updated \
                     expected={expected_value}, stored={decrypted_value}"
                );
            } else {
                panic!("Value for key={key} was changed, but it shouldn't have been");
            }
        }
    }
}
