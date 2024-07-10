# Data versioning and backward compatibility

This document explains how to save and load versioned data using the data versioning feature.

Starting from v0.6.4, **TFHE-rs** supports versioned data types. This allows you to store data and load it in the future without compatibility concerns. This feature is done by the `tfhe-versionable` crate.

This versioning scheme is compatible with all the [data formats](https://serde.rs/#data-formats) supported by serde.

## Saving and loading versioned data

To use the versioning feature, wrap your types in their versioned equivalents before serialization using the `versionize` method.
You can load serialized data with the `unversionize` function, even in newer versions of **TFHE-rs** where the data types might evolve. The `unversionize` function manages any necessary data type upgrades, ensuring compatibility.

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "0.8.0", features = ["integer","x86_64-unix"]}
tfhe-versionable = "0.2.0"
bincode = "1.3.3"
```

```rust
// main.rs

use std::io::Cursor;
use tfhe::prelude::{FheDecrypt, FheEncrypt};
use tfhe::{ClientKey, ConfigBuilder, FheUint8};
use tfhe_versionable::{Unversionize, Versionize};

fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);

    let msg = 1;
    let ct = FheUint8::encrypt(msg, &client_key);

    // Versionize the data and store it
    let mut serialized_data = Vec::new();
    let versioned_client_key = client_key.versionize();
    let versioned_ct = ct.versionize();
    bincode::serialize_into(&mut serialized_data, &versioned_client_key).unwrap();
    bincode::serialize_into(&mut serialized_data, &versioned_ct).unwrap();

    // Load the data. This can be done in the future with a more recent version of tfhe-rs
    let mut serialized_data = Cursor::new(serialized_data);
    let versioned_client_key = bincode::deserialize_from(&mut serialized_data).unwrap();
    let versioned_ct = bincode::deserialize_from(&mut serialized_data).unwrap();
    let loaded_client_key =
        ClientKey::unversionize(versioned_client_key).unwrap();
    let loaded_ct =
        FheUint8::unversionize(versioned_ct).unwrap();

    let output: u8 = loaded_ct.decrypt(&loaded_client_key);
    assert_eq!(msg, output);
}
```

### Versionize

Calling `.versionize()` on a value will add versioning tags. This is done recursively so all the subtypes that compose it are versioned too. Under the hood, it converts the value into an enum where each version of a type is represented by a new variant. The returned object can be serialized using serde:

```Rust
    let versioned_client_key = client_key.versionize();
    bincode::serialize_into(&mut serialized_data, &versioned_client_key).unwrap();
```

### Unversionize

The `Type::unversionize()` function takes a versioned value, upgrades it to the latest version of its type and removes the version tags. To do that, it matches the version in the versioned enum and eventually apply a conversion function that upgrades it to the most recent version. The resulting value can then be used inside **TFHE-rs**

```Rust
    let versioned_client_key = bincode::deserialize_from(&mut serialized_data).unwrap();
    let loaded_client_key =
        ClientKey::unversionize(versioned_client_key).unwrap();
```

# Breaking changes

When possible, data will be upgraded automatically without any kind of interraction. However, some changes might need information that are only known by the user of the library. These are called data breaking changes. In these occasions, **TFHE-rs** provides a way to upgrade these types manually.

You will find below a list of breaking changes and how to upgrade them.

# 0.6 -> 0.7
- `tfhe::integer::ciphertext::CompactCiphertextList`:
  in 0.6, these lists of ciphertext were statically typed and homogenous. Since 0.7, they are heterogeneous. The new version stores for each element an information about its type (Signed, Unsigned or Boolean). Since this information were not stored before, the list is set to be made of `Unsigned` integers by default. If that is not the case, you can set its type using the following snippet:

```rust
use std::io::Cursor;
use tfhe::integer::ciphertext::{
    CompactCiphertextList, DataKind, IntegerCompactCiphertextListCastingMode,
    IntegerCompactCiphertextListUnpackingMode, SignedRadixCiphertext,
};
use tfhe::integer::{ClientKey, CompactPublicKey};
use tfhe::shortint::parameters::classic::compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
use tfhe_versionable::{Unversionize, Versionize};

pub fn main() {
    let fhe_params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
    let num_blocks = 4usize;

    let serialized_data = {
        let client_key = ClientKey::new(fhe_params);
        let pk = CompactPublicKey::new(&client_key);

        // Encrypt a negative value
        let compact_ct = CompactCiphertextList::builder(&pk).push(u8::MAX).build();

        // Versionize the data and store it
        let mut serialized_data = Vec::new();
        let versioned_client_key = client_key.versionize();
        let versioned_ct = compact_ct.versionize();
        bincode::serialize_into(&mut serialized_data, &versioned_client_key).unwrap();
        bincode::serialize_into(&mut serialized_data, &versioned_ct).unwrap();
        serialized_data
    };

    // Now load the data, after potential breaking changes in the data format
    let mut serialized_data = Cursor::new(serialized_data);
    let versioned_client_key = bincode::deserialize_from(&mut serialized_data).unwrap();
    let versioned_ct = bincode::deserialize_from(&mut serialized_data).unwrap();
    let client_key = ClientKey::unversionize(versioned_client_key).unwrap();
    let mut compact_ct = CompactCiphertextList::unversionize(versioned_ct).unwrap();

    // Reinterpret the data as needed after the load, here we simulate the need to load Unsigned
    // data
    compact_ct
        .reinterpret_data(&[DataKind::Signed(num_blocks)])
        .unwrap();
    let expander = compact_ct
        .expand(
            IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
            IntegerCompactCiphertextListCastingMode::NoCasting,
        )
        .unwrap();
    let expanded = expander.get::<SignedRadixCiphertext>(0).unwrap().unwrap();
    let decrypted: i8 = client_key.decrypt_signed_radix(&expanded);
    // -1i8 == u8::MAX
    assert_eq!(-1i8, decrypted);
}
```

- `tfhe::{CompactFheInt, CompactFheUint, CompactFheIntList, CompactFheUintList}`:
  The types have been deprecated, they are only kept in **TFHE-rs** for backward compatibility. They can now be accessed using the `tfhe::high_level_api::backward_compatibility::integers` module. The only functionality that is still supported is to unversionize them and expand them into regular `FheInt`, `FheUint`, `Vec<FehInt>` and `Vec<FheUint>`:

```Rust
    let loaded_ct = CompactFheUint8::unversionize(versioned_ct).unwrap();
    let ct = loaded_ct.expand();
```
  Starting with v0.7, this compact list functionality is provided by the `tfhe::CompactCiphertextList` type.
