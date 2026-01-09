use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NB_CTXT};
use crate::integer::server_key::KVStore;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::{TestParameters, *};
use std::collections::BTreeMap;
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
    default_kv_store_get_update_test(params, get_executor, update_executor);
}

fn integer_default_kv_store_map(params: impl Into<TestParameters>) {
    let closure = |sks: &ServerKey,
                   store: &mut KVStore<u8, RadixCiphertext>,
                   encrypted_key: &RadixCiphertext,
                   func: &dyn Fn(RadixCiphertext) -> RadixCiphertext| {
        sks.kv_store_map(store, encrypted_key, func)
    };
    let map_executor = CpuFunctionExecutor::new(closure);
    default_kv_store_map_test(params, map_executor);
}

pub type KeyType = u8;

fn get_num_block_for_key(msg_mod: MessageModulus) -> usize {
    KeyType::BITS.div_ceil(msg_mod.0.ilog2()) as usize
}

fn default_kv_store_get_update_test<P, T1, T2>(
    params: P,
    mut kv_store_get: T1,
    mut kv_store_update: T2,
) where
    P: Into<TestParameters>,
    T1: for<'a> FunctionExecutor<
        (&'a KVStore<KeyType, RadixCiphertext>, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
    T2: for<'a> FunctionExecutor<
        (
            &'a mut KVStore<KeyType, RadixCiphertext>,
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

    let nb_blocks_key = get_num_block_for_key(params.message_modulus());

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_get.setup(&cks, sks.clone());
    kv_store_update.setup(&cks, sks);

    let num_keys = 20usize;
    let (mut map, mut clear_store) = create_filled_stores(num_keys, modulus, &cks);

    // Test modifying a key that does not exist
    for _ in 0..num_keys.div_ceil(2) {
        let key = generate_unused_key(&clear_store);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

        let (result, is_some) = kv_store_get.execute((&mut map, &encrypted_key));
        assert!(!cks.decrypt_bool(&is_some));
        assert_eq!(cks.decrypt::<u64>(&result), 0);

        let new_value = rand::random::<u64>() % modulus;
        let encrypted_new_value: RadixCiphertext = cks.encrypt(new_value);
        let is_some = kv_store_update.execute((&mut map, &encrypted_key, &encrypted_new_value));
        assert!(!cks.decrypt_bool(&is_some));

        panic_if_not_the_same(&map, &clear_store, &cks);
    }

    // Test modifying a key that exists
    for _ in 0..num_keys.div_ceil(2) {
        let key_index = rand::random_range(0..num_keys);
        let key_target = *clear_store.iter().nth(key_index).unwrap().0;
        let encrypted_key = cks.as_ref().encrypt_radix(key_target, nb_blocks_key);

        let expected_value = clear_store.get(&key_target).unwrap();

        let (result, is_some) = kv_store_get.execute((&mut map, &encrypted_key));
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

fn default_kv_store_map_test<P, T>(params: P, mut kv_store_map: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a mut KVStore<KeyType, RadixCiphertext>,
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

    let nb_blocks_key = get_num_block_for_key(params.message_modulus());

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    kv_store_map.setup(&cks, sks);

    let num_keys = 20usize;
    let (mut map, mut clear_store) = create_filled_stores(num_keys, modulus, &cks);

    let clear_function = |x: u64| -> u64 { x / 3 };
    let function = Box::new(|input: RadixCiphertext| -> RadixCiphertext {
        // Compute in the clear domain so that it is faster
        let value = cks.decrypt::<u64>(&input);
        let result = clear_function(value);
        cks.encrypt(result)
    });

    // Test modifying a key that does not exist
    for _ in 0..num_keys.div_ceil(2) {
        let key = generate_unused_key(&clear_store);
        let encrypted_key = cks.as_ref().encrypt_radix(key, nb_blocks_key);

        let (_, _, is_some) = kv_store_map.execute((&mut map, &encrypted_key, &function));
        assert!(!cks.decrypt_bool(&is_some));

        panic_if_not_the_same(&map, &clear_store, &cks);
    }

    // Test modifying a key that exists
    for _ in 0..num_keys.div_ceil(2) {
        let key_index = rand::random_range(0..num_keys);
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
/// * `modulus` - Maximum value for the random values
/// * `cks` - Client key for encryption
///
/// # Returns
/// A tuple containing the encrypted store and its clear counterpart
fn create_filled_stores(
    num_keys: usize,
    modulus: u64,
    cks: &RadixClientKey,
) -> (KVStore<KeyType, RadixCiphertext>, BTreeMap<KeyType, u64>) {
    let mut store = KVStore::new();
    let mut clear_store = BTreeMap::<u8, u64>::new();
    while clear_store.len() != num_keys {
        let (key, value) = (rand::random::<u8>(), rand::random::<u64>() % modulus);
        clear_store.insert(key, value);

        let encrypted_value = cks.encrypt(value);
        store.insert(key, encrypted_value);
    }
    assert_eq!(store.len(), clear_store.len());

    (store, clear_store)
}

/// Panics if any of the key-value pairs of the encrypted store
/// is not the same as the clear store.
fn panic_if_not_the_same(
    map: &KVStore<KeyType, RadixCiphertext>,
    clear_store: &BTreeMap<KeyType, u64>,
    cks: &RadixClientKey,
) {
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

fn generate_unused_key(clear_store: &BTreeMap<KeyType, u64>) -> u8 {
    loop {
        let key = rand::random::<u8>();
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
fn panic_if_not_properly_updated(
    map: &KVStore<KeyType, RadixCiphertext>,
    clear_store: &BTreeMap<KeyType, u64>,
    updated_key: KeyType,
    cks: &RadixClientKey,
) {
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
