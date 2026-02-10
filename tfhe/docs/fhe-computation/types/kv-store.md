# KVStore In High-level API

This document describes the `KVStore` type provided by the High-level API.


The KVStore is a storage type that associates keys to values, similar to a hash table.
In the KVStore, the keys are **clear** numbers, and values are encrypted numbers
such as `FheUint` or `FheInt`.

## Clear-key operations

The KVStore supports operations where the queried key is **clear**.
These operations are inexpensive and efficient to perform.

- `insert_with_clear_key` - insert or replace a key-value pair
- `update_with_clear_key` - update the value associated to an existing key
- `remove_with_clear_key` - remove an existing key-value pair
- `get_with_clear_key` - get the value associated to a key

## Encrypted-key operations

The KVStore also supports doing queries using an **encrypted** key.
- `get` - get the value associated to a key
- `update` - update the value associated to an already existing key
- `map` - update the value associated to an already existing key, by computing a function on it. This is faster than doing `get`, then `update`.

Encrypted-key operations do not support inserting or removing key-value pairs.


## Serialization

To serialize a `KVStore`, it must first be compressed.


```toml
# Cargo.toml

[dependencies]
tfhe = { version = "~1.5.3", features = ["integer"] }
```

```rust
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, COMP_PARAM_MESSAGE_2_CARRY_2};
use tfhe::{ConfigBuilder, generate_keys, set_server_key, KVStore, FheUint32, FheUint8,CompressedKVStore};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2)
            .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2)
            .build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let mut kv_store = KVStore::new();
    for i in 0..5u8 {
        let value = FheUint32::encrypt(u32::MAX - u32::from(i), &cks);
        let old = kv_store.insert_with_clear_key(i, value);
        assert!(old.is_none());
    }


    // Example of serialization
    // First, compress, then serialize
    let compressed = kv_store.compress().unwrap();
    let mut data = vec![];
    tfhe::safe_serialization::safe_serialize(&compressed, &mut data, 1 << 30)
        .unwrap();

    // Deserialization: deserialize, then decompress
    let compressed = 
        tfhe::safe_serialization::safe_deserialize::<CompressedKVStore<u8, FheUint32>,>(data.as_slice(), 1 << 30)
        .unwrap();
    let mut kv_store = compressed.decompress().unwrap();


    for i in 0..5u8 {
        let encrypted_key = FheUint32::encrypt(i, &cks);
        let (value, is_some) = kv_store.get(&encrypted_key);
        let is_some = is_some.decrypt(&cks);
        let value: u32 = value.decrypt(&cks);
        assert!(is_some);
        assert_eq!(value, u32::MAX - u32::from(i));
    }

    let value = FheUint32::encrypt(9682734u32, &cks);
    let encrypted_key = FheUint8::encrypt(10u8, &cks);
    let was_updated = kv_store.update(&encrypted_key, &value);
    assert!(!was_updated.decrypt(&cks));

    let encrypted_key = FheUint8::encrypt(1u8, &cks);
    let (old, new, check) = kv_store.map(&encrypted_key, |value| value * 32);
    let old: u32 = old.decrypt(&cks);
    let new: u32 = new.decrypt(&cks);
    let check = check.decrypt(&cks);
    // check encrypts true, if a matching key was found
    assert!(check);
    assert_eq!(old, u32::MAX - 1);
    assert_eq!(new, (u32::MAX - 1).wrapping_mul(32));
}
```
